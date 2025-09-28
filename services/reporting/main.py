#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Advanced Reporting Engine
Comprehensive PDF report generation with ML-powered insights and visualizations
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import base64
import io

# PDF and Document Generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

import weasyprint
from fpdf import FPDF

# Data Analysis and Visualization
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import kaleido

# Template Processing
from jinja2 import Environment, FileSystemLoader, Template
import chevron

# Image Processing
from PIL import Image as PILImage, ImageDraw, ImageFont
import cv2

# Document Processing
from docx import Document
import openpyxl
from xlsxwriter import Workbook
import pypdf

# Machine Learning for Insights
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
import tensorflow as tf
import torch
import torch.nn as nn

# NLP for Report Intelligence
import nltk
from textblob import TextBlob
import spacy

# FastAPI and async
from fastapi import FastAPI, HTTPException, BackgroundTasks, Response
from pydantic import BaseModel
import httpx
import aiofiles

# System tools
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("QuantumSentinel.Reporting")

class ReportType(str, Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TEST = "penetration_test"
    COMPLIANCE_AUDIT = "compliance_audit"
    RISK_ANALYSIS = "risk_analysis"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_INTELLIGENCE = "threat_intelligence"

class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    DOCX = "docx"
    XLSX = "xlsx"
    JSON = "json"
    XML = "xml"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    location: str
    evidence: str
    recommendation: str
    references: List[str]
    affected_assets: List[str]
    discovery_date: datetime
    service_source: str

@dataclass
class ReportMetadata:
    report_id: str
    title: str
    client_name: str
    engagement_type: str
    start_date: datetime
    end_date: datetime
    generated_date: datetime
    version: str
    confidentiality: str
    authors: List[str]

@dataclass
class ExecutiveSummary:
    overview: str
    key_findings: List[str]
    risk_rating: str
    recommendations: List[str]
    business_impact: str

class MLInsightEngine:
    """Machine Learning powered insights for security reports"""

    def __init__(self):
        self.clustering_model = None
        self.anomaly_detector = None
        self.nlp_model = None
        self._initialize_models()

    def _initialize_models(self):
        """Initialize ML models for report intelligence"""
        try:
            # Clustering for vulnerability grouping
            self.clustering_model = KMeans(n_clusters=5, random_state=42)

            # Anomaly detection for unusual findings
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)

            # Load NLP model for text analysis
            try:
                self.nlp_model = spacy.load("en_core_web_sm")
            except:
                logger.warning("SpaCy model not available, using basic NLP")

            logger.info("ML insight models initialized")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    def analyze_vulnerability_patterns(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Analyze patterns in vulnerability findings using ML"""
        if not findings:
            return {}

        try:
            # Extract features from findings
            features = self._extract_vulnerability_features(findings)

            # Cluster similar vulnerabilities
            if len(features) > 1:
                clusters = self.clustering_model.fit_predict(features)
                cluster_analysis = self._analyze_clusters(findings, clusters)
            else:
                cluster_analysis = {"clusters": [], "patterns": []}

            # Detect anomalous findings
            if len(features) > 1:
                anomalies = self.anomaly_detector.fit_predict(features)
                anomalous_findings = [findings[i] for i, anomaly in enumerate(anomalies) if anomaly == -1]
            else:
                anomalous_findings = []

            # Generate insights
            insights = self._generate_vulnerability_insights(findings, cluster_analysis, anomalous_findings)

            return {
                "cluster_analysis": cluster_analysis,
                "anomalous_findings": [asdict(f) for f in anomalous_findings],
                "insights": insights,
                "risk_trends": self._analyze_risk_trends(findings)
            }

        except Exception as e:
            logger.error(f"Vulnerability pattern analysis failed: {e}")
            return {}

    def _extract_vulnerability_features(self, findings: List[VulnerabilityFinding]) -> np.ndarray:
        """Extract numerical features from vulnerability findings"""
        features = []

        for finding in findings:
            feature_vector = [
                # Severity mapping
                {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[finding.severity.value],
                finding.cvss_score,
                len(finding.description),
                len(finding.affected_assets),
                len(finding.references),
                # Service source encoding
                hash(finding.service_source) % 100,
                # Location complexity
                len(finding.location.split("/")),
                # Days since discovery
                (datetime.utcnow() - finding.discovery_date).days
            ]
            features.append(feature_vector)

        return np.array(features)

    def _analyze_clusters(self, findings: List[VulnerabilityFinding], clusters: np.ndarray) -> Dict[str, Any]:
        """Analyze vulnerability clusters"""
        cluster_analysis = {"clusters": [], "patterns": []}

        unique_clusters = np.unique(clusters)

        for cluster_id in unique_clusters:
            cluster_findings = [findings[i] for i, c in enumerate(clusters) if c == cluster_id]

            # Analyze cluster characteristics
            severities = [f.severity.value for f in cluster_findings]
            services = [f.service_source for f in cluster_findings]

            cluster_info = {
                "cluster_id": int(cluster_id),
                "size": len(cluster_findings),
                "dominant_severity": max(set(severities), key=severities.count),
                "affected_services": list(set(services)),
                "avg_cvss": np.mean([f.cvss_score for f in cluster_findings]),
                "sample_titles": [f.title for f in cluster_findings[:3]]
            }

            cluster_analysis["clusters"].append(cluster_info)

        # Identify patterns
        if len(unique_clusters) > 1:
            cluster_analysis["patterns"] = [
                f"Found {len(unique_clusters)} distinct vulnerability patterns",
                f"Largest cluster contains {max(c['size'] for c in cluster_analysis['clusters'])} vulnerabilities",
                f"Services with most vulnerabilities: {self._get_top_vulnerable_services(findings)}"
            ]

        return cluster_analysis

    def _generate_vulnerability_insights(self, findings: List[VulnerabilityFinding],
                                       cluster_analysis: Dict, anomalous_findings: List) -> List[str]:
        """Generate actionable insights from vulnerability analysis"""
        insights = []

        # Severity distribution insights
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        if severity_counts.get("critical", 0) > 0:
            insights.append(f"URGENT: {severity_counts['critical']} critical vulnerabilities require immediate attention")

        # Service-based insights
        service_vuln_count = {}
        for finding in findings:
            service_vuln_count[finding.service_source] = service_vuln_count.get(finding.service_source, 0) + 1

        if service_vuln_count:
            top_service = max(service_vuln_count.items(), key=lambda x: x[1])
            insights.append(f"Service '{top_service[0]}' has the highest vulnerability count ({top_service[1]})")

        # CVSS score insights
        avg_cvss = np.mean([f.cvss_score for f in findings])
        if avg_cvss > 7.0:
            insights.append(f"High average CVSS score ({avg_cvss:.1f}) indicates severe security posture")

        # Anomaly insights
        if anomalous_findings:
            insights.append(f"{len(anomalous_findings)} unusual vulnerabilities detected that require special attention")

        # Cluster insights
        if cluster_analysis.get("clusters"):
            largest_cluster = max(cluster_analysis["clusters"], key=lambda x: x["size"])
            insights.append(f"Largest vulnerability pattern affects {largest_cluster['size']} findings in '{largest_cluster['affected_services'][0] if largest_cluster['affected_services'] else 'unknown'}' service")

        return insights

    def _analyze_risk_trends(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Analyze risk trends over time"""
        if not findings:
            return {}

        # Group by discovery date
        findings_by_date = {}
        for finding in findings:
            date_key = finding.discovery_date.date()
            if date_key not in findings_by_date:
                findings_by_date[date_key] = []
            findings_by_date[date_key].append(finding)

        # Calculate trend metrics
        dates = sorted(findings_by_date.keys())
        daily_counts = [len(findings_by_date[date]) for date in dates]
        daily_avg_cvss = [np.mean([f.cvss_score for f in findings_by_date[date]]) for date in dates]

        return {
            "discovery_timeline": {str(date): count for date, count in zip(dates, daily_counts)},
            "avg_cvss_timeline": {str(date): score for date, score in zip(dates, daily_avg_cvss)},
            "trend_direction": "increasing" if len(daily_counts) > 1 and daily_counts[-1] > daily_counts[0] else "stable"
        }

    def _get_top_vulnerable_services(self, findings: List[VulnerabilityFinding], top_n: int = 3) -> List[str]:
        """Get top vulnerable services"""
        service_counts = {}
        for finding in findings:
            service_counts[finding.service_source] = service_counts.get(finding.service_source, 0) + 1

        return [service for service, _ in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]]

class VisualizationEngine:
    """Advanced visualization engine for security reports"""

    def __init__(self):
        # Set matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")

    def create_vulnerability_distribution_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create vulnerability distribution pie chart"""
        if not findings:
            return ""

        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        # Create plotly pie chart
        fig = go.Figure(data=[
            go.Pie(
                labels=list(severity_counts.keys()),
                values=list(severity_counts.values()),
                hole=.3,
                marker_colors=['#FF6B6B', '#FF8E53', '#4ECDC4', '#45B7D1', '#96CEB4']
            )
        ])

        fig.update_layout(
            title="Vulnerability Distribution by Severity",
            font=dict(size=14),
            showlegend=True
        )

        # Convert to base64 image
        img_bytes = fig.to_image(format="png", width=600, height=400)
        img_base64 = base64.b64encode(img_bytes).decode()

        return img_base64

    def create_cvss_score_histogram(self, findings: List[VulnerabilityFinding]) -> str:
        """Create CVSS score distribution histogram"""
        if not findings:
            return ""

        cvss_scores = [f.cvss_score for f in findings]

        fig = go.Figure(data=[
            go.Histogram(
                x=cvss_scores,
                nbinsx=20,
                marker_color='rgba(55, 128, 191, 0.7)',
                marker_line=dict(color='rgba(55, 128, 191, 1.0)', width=1)
            )
        ])

        fig.update_layout(
            title="CVSS Score Distribution",
            xaxis_title="CVSS Score",
            yaxis_title="Number of Vulnerabilities",
            font=dict(size=14)
        )

        img_bytes = fig.to_image(format="png", width=600, height=400)
        img_base64 = base64.b64encode(img_bytes).decode()

        return img_base64

    def create_timeline_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create vulnerability discovery timeline"""
        if not findings:
            return ""

        # Group by date
        findings_by_date = {}
        for finding in findings:
            date_key = finding.discovery_date.date()
            findings_by_date[date_key] = findings_by_date.get(date_key, 0) + 1

        dates = sorted(findings_by_date.keys())
        counts = [findings_by_date[date] for date in dates]

        fig = go.Figure(data=[
            go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                line=dict(color='rgb(55, 128, 191)', width=3),
                marker=dict(size=8)
            )
        ])

        fig.update_layout(
            title="Vulnerability Discovery Timeline",
            xaxis_title="Date",
            yaxis_title="Vulnerabilities Discovered",
            font=dict(size=14)
        )

        img_bytes = fig.to_image(format="png", width=800, height=400)
        img_base64 = base64.b64encode(img_bytes).decode()

        return img_base64

    def create_service_vulnerability_matrix(self, findings: List[VulnerabilityFinding]) -> str:
        """Create service vs severity vulnerability matrix"""
        if not findings:
            return ""

        # Create matrix data
        services = list(set(f.service_source for f in findings))
        severities = ['critical', 'high', 'medium', 'low', 'info']

        matrix_data = []
        for service in services:
            row = []
            for severity in severities:
                count = sum(1 for f in findings if f.service_source == service and f.severity.value == severity)
                row.append(count)
            matrix_data.append(row)

        fig = go.Figure(data=go.Heatmap(
            z=matrix_data,
            x=severities,
            y=services,
            colorscale='Reds',
            showscale=True
        ))

        fig.update_layout(
            title="Service vs Severity Vulnerability Matrix",
            xaxis_title="Severity",
            yaxis_title="Service",
            font=dict(size=14)
        )

        img_bytes = fig.to_image(format="png", width=800, height=600)
        img_base64 = base64.b64encode(img_bytes).decode()

        return img_base64

class PDFReportGenerator:
    """Advanced PDF report generation with ReportLab"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.visualization_engine = VisualizationEngine()

        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2C3E50')
        )

        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#34495E')
        )

    def generate_comprehensive_report(self, metadata: ReportMetadata,
                                    findings: List[VulnerabilityFinding],
                                    executive_summary: ExecutiveSummary,
                                    ml_insights: Dict[str, Any]) -> bytes:
        """Generate comprehensive PDF report"""

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=1*inch)

        # Story elements
        story = []

        # Title page
        story.extend(self._create_title_page(metadata))
        story.append(PageBreak())

        # Table of contents
        story.extend(self._create_table_of_contents())
        story.append(PageBreak())

        # Executive summary
        story.extend(self._create_executive_summary_section(executive_summary))
        story.append(PageBreak())

        # Methodology
        story.extend(self._create_methodology_section())
        story.append(PageBreak())

        # Key findings with visualizations
        story.extend(self._create_findings_overview(findings))
        story.append(PageBreak())

        # ML insights section
        if ml_insights:
            story.extend(self._create_ml_insights_section(ml_insights))
            story.append(PageBreak())

        # Detailed findings
        story.extend(self._create_detailed_findings_section(findings))
        story.append(PageBreak())

        # Risk analysis
        story.extend(self._create_risk_analysis_section(findings))
        story.append(PageBreak())

        # Recommendations
        story.extend(self._create_recommendations_section(findings, executive_summary))
        story.append(PageBreak())

        # Appendices
        story.extend(self._create_appendices())

        # Build PDF
        doc.build(story)

        # Get PDF bytes
        buffer.seek(0)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    def _create_title_page(self, metadata: ReportMetadata) -> List:
        """Create title page"""
        elements = []

        # Title
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(metadata.title, self.title_style))
        elements.append(Spacer(1, 0.5*inch))

        # Subtitle
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            alignment=1,
            textColor=colors.HexColor('#7F8C8D')
        )
        elements.append(Paragraph(f"Security Assessment Report for {metadata.client_name}", subtitle_style))
        elements.append(Spacer(1, 1*inch))

        # Metadata table
        metadata_data = [
            ['Report ID:', metadata.report_id],
            ['Engagement Type:', metadata.engagement_type],
            ['Assessment Period:', f"{metadata.start_date.strftime('%Y-%m-%d')} to {metadata.end_date.strftime('%Y-%m-%d')}"],
            ['Report Generated:', metadata.generated_date.strftime('%Y-%m-%d %H:%M:%S')],
            ['Version:', metadata.version],
            ['Confidentiality:', metadata.confidentiality],
            ['Authors:', ', '.join(metadata.authors)]
        ]

        metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(metadata_table)
        elements.append(Spacer(1, 1*inch))

        # Disclaimer
        disclaimer_text = """
        <b>CONFIDENTIAL</b><br/>
        This report contains confidential and proprietary information.
        It is intended solely for the use of the client organization
        and should not be disclosed to third parties without explicit consent.
        """
        disclaimer_style = ParagraphStyle(
            'Disclaimer',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=1,
            textColor=colors.HexColor('#E74C3C'),
            borderWidth=1,
            borderColor=colors.HexColor('#E74C3C'),
            borderPadding=10
        )
        elements.append(Paragraph(disclaimer_text, disclaimer_style))

        return elements

    def _create_table_of_contents(self) -> List:
        """Create table of contents"""
        elements = []

        elements.append(Paragraph("Table of Contents", self.title_style))
        elements.append(Spacer(1, 20))

        toc_items = [
            ("1. Executive Summary", "3"),
            ("2. Methodology", "4"),
            ("3. Key Findings Overview", "5"),
            ("4. ML-Powered Insights", "6"),
            ("5. Detailed Vulnerability Findings", "7"),
            ("6. Risk Analysis", "15"),
            ("7. Recommendations", "16"),
            ("8. Appendices", "17")
        ]

        toc_data = [[item[0], item[1]] for item in toc_items]
        toc_table = Table(toc_data, colWidths=[4*inch, 1*inch])
        toc_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7'))
        ]))

        elements.append(toc_table)

        return elements

    def _create_executive_summary_section(self, summary: ExecutiveSummary) -> List:
        """Create executive summary section"""
        elements = []

        elements.append(Paragraph("Executive Summary", self.title_style))
        elements.append(Spacer(1, 20))

        # Overview
        elements.append(Paragraph("Overview", self.heading_style))
        elements.append(Paragraph(summary.overview, self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Risk Rating
        risk_colors = {
            'Critical': colors.HexColor('#E74C3C'),
            'High': colors.HexColor('#E67E22'),
            'Medium': colors.HexColor('#F39C12'),
            'Low': colors.HexColor('#27AE60')
        }
        risk_color = risk_colors.get(summary.risk_rating, colors.black)

        risk_style = ParagraphStyle(
            'RiskRating',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=risk_color,
            fontName='Helvetica-Bold'
        )
        elements.append(Paragraph("Overall Risk Rating", self.heading_style))
        elements.append(Paragraph(f"<b>{summary.risk_rating}</b>", risk_style))
        elements.append(Spacer(1, 15))

        # Key Findings
        elements.append(Paragraph("Key Findings", self.heading_style))
        for i, finding in enumerate(summary.key_findings, 1):
            elements.append(Paragraph(f"{i}. {finding}", self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Business Impact
        elements.append(Paragraph("Business Impact", self.heading_style))
        elements.append(Paragraph(summary.business_impact, self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Recommendations
        elements.append(Paragraph("Priority Recommendations", self.heading_style))
        for i, rec in enumerate(summary.recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))

        return elements

    def _create_methodology_section(self) -> List:
        """Create methodology section"""
        elements = []

        elements.append(Paragraph("Assessment Methodology", self.title_style))
        elements.append(Spacer(1, 20))

        methodology_text = """
        QuantumSentinel-Nexus employs a comprehensive, multi-layered approach to security assessment:

        <b>1. Automated Vulnerability Scanning</b><br/>
        • SAST/DAST analysis using industry-leading tools<br/>
        • Network protocol fuzzing and analysis<br/>
        • Web application security testing<br/>

        <b>2. Machine Learning Enhanced Analysis</b><br/>
        • AI-powered vulnerability pattern recognition<br/>
        • Anomaly detection for zero-day identification<br/>
        • Risk correlation and impact analysis<br/>

        <b>3. Internet Bug Bounty Research</b><br/>
        • 24/7 automated vulnerability research<br/>
        • Academic paper and CVE database analysis<br/>
        • Emerging threat intelligence gathering<br/>

        <b>4. Manual Security Review</b><br/>
        • Expert validation of automated findings<br/>
        • Business logic vulnerability assessment<br/>
        • Custom exploit development and validation<br/>

        <b>5. Comprehensive Reporting</b><br/>
        • Executive and technical reporting<br/>
        • Risk-based prioritization<br/>
        • Actionable remediation guidance<br/>
        """

        elements.append(Paragraph(methodology_text, self.styles['Normal']))

        return elements

    def _create_findings_overview(self, findings: List[VulnerabilityFinding]) -> List:
        """Create findings overview with visualizations"""
        elements = []

        elements.append(Paragraph("Key Findings Overview", self.title_style))
        elements.append(Spacer(1, 20))

        if not findings:
            elements.append(Paragraph("No vulnerabilities were identified during this assessment.", self.styles['Normal']))
            return elements

        # Summary statistics
        total_findings = len(findings)
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        avg_cvss = np.mean([f.cvss_score for f in findings])

        stats_text = f"""
        <b>Assessment Results Summary:</b><br/>
        • Total Vulnerabilities Identified: {total_findings}<br/>
        • Critical: {severity_counts.get('critical', 0)}<br/>
        • High: {severity_counts.get('high', 0)}<br/>
        • Medium: {severity_counts.get('medium', 0)}<br/>
        • Low: {severity_counts.get('low', 0)}<br/>
        • Info: {severity_counts.get('info', 0)}<br/>
        • Average CVSS Score: {avg_cvss:.1f}<br/>
        """

        elements.append(Paragraph(stats_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add visualizations
        try:
            # Vulnerability distribution chart
            dist_chart = self.visualization_engine.create_vulnerability_distribution_chart(findings)
            if dist_chart:
                chart_image = self._create_chart_image(dist_chart, "Vulnerability Distribution")
                elements.append(chart_image)
                elements.append(Spacer(1, 20))

            # CVSS histogram
            cvss_chart = self.visualization_engine.create_cvss_score_histogram(findings)
            if cvss_chart:
                chart_image = self._create_chart_image(cvss_chart, "CVSS Score Distribution")
                elements.append(chart_image)

        except Exception as e:
            logger.error(f"Failed to create charts: {e}")

        return elements

    def _create_chart_image(self, base64_image: str, caption: str) -> Image:
        """Create ReportLab Image from base64 data"""
        try:
            # Decode base64 image
            image_data = base64.b64decode(base64_image)

            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
                tmp_file.write(image_data)
                tmp_file_path = tmp_file.name

            # Create ReportLab Image
            img = Image(tmp_file_path, width=5*inch, height=3*inch)

            # Clean up
            os.unlink(tmp_file_path)

            return img

        except Exception as e:
            logger.error(f"Failed to create chart image: {e}")
            return Paragraph(f"[Chart: {caption}]", self.styles['Normal'])

    def _create_ml_insights_section(self, ml_insights: Dict[str, Any]) -> List:
        """Create ML insights section"""
        elements = []

        elements.append(Paragraph("AI-Powered Security Insights", self.title_style))
        elements.append(Spacer(1, 20))

        if not ml_insights:
            elements.append(Paragraph("No ML insights available for this assessment.", self.styles['Normal']))
            return elements

        # Insights overview
        insights = ml_insights.get('insights', [])
        if insights:
            elements.append(Paragraph("Key AI-Generated Insights", self.heading_style))
            for insight in insights:
                elements.append(Paragraph(f"• {insight}", self.styles['Normal']))
            elements.append(Spacer(1, 15))

        # Cluster analysis
        cluster_analysis = ml_insights.get('cluster_analysis', {})
        if cluster_analysis.get('clusters'):
            elements.append(Paragraph("Vulnerability Pattern Analysis", self.heading_style))
            for cluster in cluster_analysis['clusters']:
                cluster_text = f"""
                <b>Pattern {cluster['cluster_id'] + 1}:</b> {cluster['size']} vulnerabilities<br/>
                • Dominant Severity: {cluster['dominant_severity'].title()}<br/>
                • Average CVSS: {cluster['avg_cvss']:.1f}<br/>
                • Affected Services: {', '.join(cluster['affected_services'])}<br/>
                """
                elements.append(Paragraph(cluster_text, self.styles['Normal']))
            elements.append(Spacer(1, 15))

        # Anomalies
        anomalous_findings = ml_insights.get('anomalous_findings', [])
        if anomalous_findings:
            elements.append(Paragraph("Anomalous Findings Requiring Special Attention", self.heading_style))
            for anomaly in anomalous_findings[:3]:  # Show top 3
                elements.append(Paragraph(f"• {anomaly['title']} (CVSS: {anomaly['cvss_score']})", self.styles['Normal']))

        return elements

    def _create_detailed_findings_section(self, findings: List[VulnerabilityFinding]) -> List:
        """Create detailed findings section"""
        elements = []

        elements.append(Paragraph("Detailed Vulnerability Findings", self.title_style))
        elements.append(Spacer(1, 20))

        if not findings:
            elements.append(Paragraph("No detailed findings to report.", self.styles['Normal']))
            return elements

        # Sort findings by severity and CVSS score
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings,
                               key=lambda x: (severity_order[x.severity.value], -x.cvss_score))

        for i, finding in enumerate(sorted_findings, 1):
            # Finding header
            severity_colors = {
                'critical': colors.HexColor('#E74C3C'),
                'high': colors.HexColor('#E67E22'),
                'medium': colors.HexColor('#F39C12'),
                'low': colors.HexColor('#27AE60'),
                'info': colors.HexColor('#3498DB')
            }

            header_style = ParagraphStyle(
                'FindingHeader',
                parent=self.styles['Heading2'],
                fontSize=14,
                textColor=severity_colors[finding.severity.value]
            )

            elements.append(Paragraph(f"{i}. {finding.title}", header_style))
            elements.append(Spacer(1, 10))

            # Finding details table
            finding_data = [
                ['Severity:', finding.severity.value.title()],
                ['CVSS Score:', str(finding.cvss_score)],
                ['Location:', finding.location],
                ['Source Service:', finding.service_source],
                ['Discovery Date:', finding.discovery_date.strftime('%Y-%m-%d')],
                ['Affected Assets:', ', '.join(finding.affected_assets) if finding.affected_assets else 'N/A']
            ]

            finding_table = Table(finding_data, colWidths=[1.5*inch, 4*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7'))
            ]))

            elements.append(finding_table)
            elements.append(Spacer(1, 10))

            # Description
            elements.append(Paragraph("<b>Description:</b>", self.styles['Normal']))
            elements.append(Paragraph(finding.description, self.styles['Normal']))
            elements.append(Spacer(1, 8))

            # Evidence
            elements.append(Paragraph("<b>Evidence:</b>", self.styles['Normal']))
            evidence_style = ParagraphStyle(
                'Evidence',
                parent=self.styles['Normal'],
                fontName='Courier',
                fontSize=8,
                backgroundColor=colors.HexColor('#F8F9FA'),
                borderWidth=1,
                borderColor=colors.HexColor('#E9ECEF'),
                borderPadding=5
            )
            elements.append(Paragraph(finding.evidence[:500] + "..." if len(finding.evidence) > 500 else finding.evidence, evidence_style))
            elements.append(Spacer(1, 8))

            # Recommendation
            elements.append(Paragraph("<b>Recommendation:</b>", self.styles['Normal']))
            elements.append(Paragraph(finding.recommendation, self.styles['Normal']))
            elements.append(Spacer(1, 8))

            # References
            if finding.references:
                elements.append(Paragraph("<b>References:</b>", self.styles['Normal']))
                for ref in finding.references:
                    elements.append(Paragraph(f"• {ref}", self.styles['Normal']))

            elements.append(Spacer(1, 20))

            # Page break after every 3 findings
            if i % 3 == 0 and i < len(sorted_findings):
                elements.append(PageBreak())

        return elements

    def _create_risk_analysis_section(self, findings: List[VulnerabilityFinding]) -> List:
        """Create risk analysis section"""
        elements = []

        elements.append(Paragraph("Risk Analysis", self.title_style))
        elements.append(Spacer(1, 20))

        if not findings:
            elements.append(Paragraph("No risks identified.", self.styles['Normal']))
            return elements

        # Risk metrics
        total_findings = len(findings)
        critical_high = len([f for f in findings if f.severity.value in ['critical', 'high']])
        avg_cvss = np.mean([f.cvss_score for f in findings])

        # Risk level determination
        if critical_high > 5 or avg_cvss > 8.0:
            risk_level = "CRITICAL"
            risk_color = colors.HexColor('#E74C3C')
        elif critical_high > 2 or avg_cvss > 6.0:
            risk_level = "HIGH"
            risk_color = colors.HexColor('#E67E22')
        elif total_findings > 10 or avg_cvss > 4.0:
            risk_level = "MEDIUM"
            risk_color = colors.HexColor('#F39C12')
        else:
            risk_level = "LOW"
            risk_color = colors.HexColor('#27AE60')

        risk_style = ParagraphStyle(
            'RiskLevel',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=risk_color,
            fontName='Helvetica-Bold'
        )

        elements.append(Paragraph("Overall Security Risk Level", self.heading_style))
        elements.append(Paragraph(f"<b>{risk_level}</b>", risk_style))
        elements.append(Spacer(1, 15))

        # Risk factors
        risk_factors = []
        if critical_high > 0:
            risk_factors.append(f"{critical_high} critical/high severity vulnerabilities present")
        if avg_cvss > 7.0:
            risk_factors.append(f"High average CVSS score ({avg_cvss:.1f})")

        services_affected = len(set(f.service_source for f in findings))
        if services_affected > 3:
            risk_factors.append(f"Multiple services affected ({services_affected} services)")

        if risk_factors:
            elements.append(Paragraph("Key Risk Factors", self.heading_style))
            for factor in risk_factors:
                elements.append(Paragraph(f"• {factor}", self.styles['Normal']))
            elements.append(Spacer(1, 15))

        # Risk timeline
        elements.append(Paragraph("Risk Remediation Timeline", self.heading_style))
        timeline_text = """
        <b>Immediate (0-30 days):</b> Address all critical vulnerabilities<br/>
        <b>Short-term (1-3 months):</b> Remediate high severity issues<br/>
        <b>Medium-term (3-6 months):</b> Fix medium severity vulnerabilities<br/>
        <b>Long-term (6+ months):</b> Address low/info level findings<br/>
        """
        elements.append(Paragraph(timeline_text, self.styles['Normal']))

        return elements

    def _create_recommendations_section(self, findings: List[VulnerabilityFinding],
                                      summary: ExecutiveSummary) -> List:
        """Create recommendations section"""
        elements = []

        elements.append(Paragraph("Security Recommendations", self.title_style))
        elements.append(Spacer(1, 20))

        # Priority recommendations from executive summary
        elements.append(Paragraph("Priority Actions", self.heading_style))
        for i, rec in enumerate(summary.recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Technical recommendations based on findings
        elements.append(Paragraph("Technical Recommendations", self.heading_style))

        # Generate recommendations based on finding patterns
        service_recommendations = self._generate_service_recommendations(findings)
        for service, recs in service_recommendations.items():
            elements.append(Paragraph(f"<b>{service} Service:</b>", self.styles['Normal']))
            for rec in recs:
                elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 10))

        # General security improvements
        elements.append(Paragraph("General Security Improvements", self.heading_style))
        general_recs = [
            "Implement automated security scanning in CI/CD pipeline",
            "Establish regular penetration testing schedule",
            "Deploy Web Application Firewall (WAF)",
            "Enhance monitoring and incident response capabilities",
            "Conduct security awareness training for development teams"
        ]

        for rec in general_recs:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))

        return elements

    def _generate_service_recommendations(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        """Generate service-specific recommendations"""
        recommendations = {}

        # Group findings by service
        service_findings = {}
        for finding in findings:
            if finding.service_source not in service_findings:
                service_findings[finding.service_source] = []
            service_findings[finding.service_source].append(finding)

        for service, service_vulns in service_findings.items():
            recs = []

            # Count vulnerabilities by type
            vuln_types = [f.vulnerability_type for f in service_vulns if f.vulnerability_type]

            if any('sql_injection' in vt for vt in vuln_types if vt):
                recs.append("Implement parameterized queries and input validation")

            if any('xss' in vt for vt in vuln_types if vt):
                recs.append("Apply output encoding and Content Security Policy")

            if any('buffer_overflow' in vt for vt in vuln_types if vt):
                recs.append("Review memory management and implement bounds checking")

            # Generic recommendations based on severity
            critical_count = len([f for f in service_vulns if f.severity.value == 'critical'])
            if critical_count > 0:
                recs.append(f"URGENT: Address {critical_count} critical vulnerabilities immediately")

            avg_cvss = np.mean([f.cvss_score for f in service_vulns])
            if avg_cvss > 7.0:
                recs.append("Conduct thorough security review and testing")

            if not recs:
                recs.append("Continue monitoring and maintain security posture")

            recommendations[service] = recs

        return recommendations

    def _create_appendices(self) -> List:
        """Create appendices section"""
        elements = []

        elements.append(Paragraph("Appendices", self.title_style))
        elements.append(Spacer(1, 20))

        # Appendix A: Vulnerability Classification
        elements.append(Paragraph("Appendix A: Vulnerability Classification", self.heading_style))
        classification_text = """
        <b>CVSS Scoring Guidelines:</b><br/>
        • Critical (9.0-10.0): Immediate threat requiring urgent action<br/>
        • High (7.0-8.9): Significant risk requiring prompt remediation<br/>
        • Medium (4.0-6.9): Moderate risk requiring timely attention<br/>
        • Low (0.1-3.9): Minor risk for future consideration<br/>
        • Info (0.0): Informational findings for awareness<br/>
        """
        elements.append(Paragraph(classification_text, self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Appendix B: Tools and Methodology
        elements.append(Paragraph("Appendix B: Assessment Tools", self.heading_style))
        tools_text = """
        <b>Automated Scanning Tools:</b><br/>
        • SAST/DAST: Bandit, Safety, Semgrep<br/>
        • Network Analysis: Nmap, custom protocol fuzzers<br/>
        • Web Application: Custom ML-enhanced testing framework<br/>
        • Fuzzing: Advanced mutation engines with ML guidance<br/>

        <b>Machine Learning Components:</b><br/>
        • Vulnerability pattern recognition using clustering algorithms<br/>
        • Anomaly detection for zero-day identification<br/>
        • Natural language processing for threat intelligence<br/>
        """
        elements.append(Paragraph(tools_text, self.styles['Normal']))

        return elements

class ReportingEngine:
    """Main reporting engine orchestrator"""

    def __init__(self):
        self.pdf_generator = PDFReportGenerator()
        self.ml_insights = MLInsightEngine()
        self.report_storage = {}

    async def generate_comprehensive_report(self,
                                          scan_results: Dict[str, Any],
                                          report_type: ReportType = ReportType.TECHNICAL_DETAILED,
                                          format: ReportFormat = ReportFormat.PDF) -> Dict[str, Any]:
        """Generate comprehensive security report"""

        report_id = str(uuid.uuid4())
        logger.info(f"Generating {report_type.value} report {report_id}")

        try:
            # Extract findings from scan results
            findings = self._extract_findings_from_results(scan_results)

            # Generate ML insights
            ml_insights = self.ml_insights.analyze_vulnerability_patterns(findings)

            # Create metadata
            metadata = ReportMetadata(
                report_id=report_id,
                title="QuantumSentinel-Nexus Security Assessment",
                client_name=scan_results.get('client_name', 'Confidential Client'),
                engagement_type=report_type.value.replace('_', ' ').title(),
                start_date=datetime.utcnow() - timedelta(days=7),
                end_date=datetime.utcnow(),
                generated_date=datetime.utcnow(),
                version="1.0",
                confidentiality="CONFIDENTIAL",
                authors=["QuantumSentinel-Nexus Security Team"]
            )

            # Generate executive summary
            executive_summary = self._generate_executive_summary(findings, ml_insights)

            # Generate report based on format
            if format == ReportFormat.PDF:
                report_content = self.pdf_generator.generate_comprehensive_report(
                    metadata, findings, executive_summary, ml_insights
                )
                content_type = "application/pdf"
                file_extension = "pdf"
            else:
                # For other formats, return JSON for now
                report_content = json.dumps({
                    'metadata': asdict(metadata),
                    'executive_summary': asdict(executive_summary),
                    'findings': [asdict(f) for f in findings],
                    'ml_insights': ml_insights
                }, indent=2, default=str).encode()
                content_type = "application/json"
                file_extension = "json"

            # Store report
            self.report_storage[report_id] = {
                'metadata': metadata,
                'content': report_content,
                'content_type': content_type,
                'file_extension': file_extension,
                'generated_at': datetime.utcnow(),
                'findings_count': len(findings),
                'vulnerabilities_count': len([f for f in findings if f.severity.value in ['critical', 'high', 'medium']])
            }

            logger.info(f"Report {report_id} generated successfully with {len(findings)} findings")

            return {
                'report_id': report_id,
                'status': 'completed',
                'report_type': report_type.value,
                'format': format.value,
                'findings_count': len(findings),
                'vulnerabilities_count': len([f for f in findings if f.severity.value in ['critical', 'high', 'medium']]),
                'file_size': len(report_content),
                'generated_at': metadata.generated_date.isoformat()
            }

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise

    def _extract_findings_from_results(self, scan_results: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Extract vulnerability findings from scan results"""
        findings = []

        # Extract findings from different services
        all_findings = scan_results.get('findings', [])

        for finding_data in all_findings:
            try:
                finding = VulnerabilityFinding(
                    id=finding_data.get('id', str(uuid.uuid4())),
                    title=finding_data.get('title', 'Unknown Vulnerability'),
                    description=finding_data.get('description', 'No description available'),
                    severity=SeverityLevel(finding_data.get('severity', 'low')),
                    cvss_score=float(finding_data.get('cvss_score', 0.0)),
                    location=finding_data.get('location', 'Unknown'),
                    evidence=finding_data.get('evidence', 'No evidence provided'),
                    recommendation=finding_data.get('recommendation', 'Review and validate finding'),
                    references=finding_data.get('references', []),
                    affected_assets=finding_data.get('affected_assets', []),
                    discovery_date=datetime.utcnow(),
                    service_source=finding_data.get('service', 'unknown')
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue

        return findings

    def _generate_executive_summary(self, findings: List[VulnerabilityFinding],
                                   ml_insights: Dict[str, Any]) -> ExecutiveSummary:
        """Generate executive summary"""

        total_findings = len(findings)
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        # Determine overall risk rating
        critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        if critical_high > 5:
            risk_rating = "Critical"
        elif critical_high > 2:
            risk_rating = "High"
        elif total_findings > 10:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"

        # Generate overview
        if total_findings == 0:
            overview = "The security assessment revealed no significant vulnerabilities in the tested systems."
        else:
            overview = f"The security assessment identified {total_findings} findings across the tested infrastructure, with {critical_high} requiring immediate attention."

        # Key findings
        key_findings = []
        if severity_counts.get('critical', 0) > 0:
            key_findings.append(f"{severity_counts['critical']} critical vulnerabilities requiring immediate remediation")

        if severity_counts.get('high', 0) > 0:
            key_findings.append(f"{severity_counts['high']} high severity vulnerabilities identified")

        # Add ML insights to key findings
        ml_insights_list = ml_insights.get('insights', [])
        if ml_insights_list:
            key_findings.extend(ml_insights_list[:2])  # Add top 2 ML insights

        if not key_findings:
            key_findings = ["No significant security issues identified"]

        # Business impact
        if critical_high > 0:
            business_impact = "The identified vulnerabilities pose significant risk to business operations and require immediate attention to prevent potential security incidents."
        elif total_findings > 5:
            business_impact = "While no critical issues were found, the accumulated risk from multiple vulnerabilities requires systematic remediation."
        else:
            business_impact = "The security posture is generally good with minimal risk to business operations."

        # Recommendations
        recommendations = []
        if severity_counts.get('critical', 0) > 0:
            recommendations.append("Immediately address all critical vulnerabilities")
        if severity_counts.get('high', 0) > 0:
            recommendations.append("Develop remediation plan for high severity issues")
        recommendations.append("Implement continuous security monitoring")
        recommendations.append("Establish regular security assessment schedule")

        return ExecutiveSummary(
            overview=overview,
            key_findings=key_findings,
            risk_rating=risk_rating,
            recommendations=recommendations,
            business_impact=business_impact
        )

    def get_report(self, report_id: str) -> Dict[str, Any]:
        """Get generated report"""
        if report_id not in self.report_storage:
            raise ValueError(f"Report {report_id} not found")

        return self.report_storage[report_id]

    def list_reports(self) -> List[Dict[str, Any]]:
        """List all generated reports"""
        reports = []
        for report_id, report_data in self.report_storage.items():
            reports.append({
                'report_id': report_id,
                'title': report_data['metadata'].title,
                'generated_at': report_data['generated_at'].isoformat(),
                'findings_count': report_data['findings_count'],
                'vulnerabilities_count': report_data['vulnerabilities_count'],
                'file_size': report_data['file_size']
            })

        return sorted(reports, key=lambda x: x['generated_at'], reverse=True)

# Initialize FastAPI app
app = FastAPI(
    title="QuantumSentinel Advanced Reporting Engine",
    description="Comprehensive security report generation with ML-powered insights and visualizations",
    version="2.0.0"
)

# Global reporting engine
reporting_engine = ReportingEngine()

# Pydantic models for API
class ReportGenerationRequest(BaseModel):
    scan_results: Dict[str, Any]
    report_type: ReportType = ReportType.TECHNICAL_DETAILED
    format: ReportFormat = ReportFormat.PDF
    client_name: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Initialize reporting service on startup"""
    logger.info("QuantumSentinel Advanced Reporting Engine starting up...")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "advanced-reporting",
        "timestamp": datetime.utcnow().isoformat(),
        "reports_generated": len(reporting_engine.report_storage)
    }

@app.post("/generate")
async def generate_report(request: ReportGenerationRequest):
    """Generate comprehensive security report"""
    try:
        # Add client name to scan results if provided
        if request.client_name:
            request.scan_results['client_name'] = request.client_name

        result = await reporting_engine.generate_comprehensive_report(
            scan_results=request.scan_results,
            report_type=request.report_type,
            format=request.format
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download generated report"""
    try:
        report_data = reporting_engine.get_report(report_id)

        filename = f"security_report_{report_id}.{report_data['file_extension']}"

        return Response(
            content=report_data['content'],
            media_type=report_data['content_type'],
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/reports/{report_id}")
async def get_report_info(report_id: str):
    """Get report information"""
    try:
        report_data = reporting_engine.get_report(report_id)

        return {
            'report_id': report_id,
            'metadata': asdict(report_data['metadata']),
            'generated_at': report_data['generated_at'].isoformat(),
            'findings_count': report_data['findings_count'],
            'vulnerabilities_count': report_data['vulnerabilities_count'],
            'file_size': report_data['file_size'],
            'content_type': report_data['content_type']
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/reports")
async def list_reports():
    """List all generated reports"""
    return {
        'reports': reporting_engine.list_reports()
    }

@app.get("/statistics")
async def get_statistics():
    """Get reporting statistics"""
    reports = reporting_engine.list_reports()

    return {
        'total_reports': len(reports),
        'total_findings': sum(r['findings_count'] for r in reports),
        'total_vulnerabilities': sum(r['vulnerabilities_count'] for r in reports),
        'recent_reports': len([r for r in reports if
                             datetime.fromisoformat(r['generated_at']) > datetime.utcnow() - timedelta(days=7)])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)