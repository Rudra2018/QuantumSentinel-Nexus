#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Binary Analysis Comprehensive Workflow
===========================================================

A comprehensive binary analysis workflow that supports multiple binary formats
and provides extensive security analysis capabilities.

Author: QuantumSentinel Team
Version: 3.0
Date: 2024
"""

import asyncio
import argparse
import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_engines.binary.enhanced_binary_engine import EnhancedBinaryEngine
from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector
from quantum_cli import QuantumCLI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BinaryAnalysisWorkflow:
    """Comprehensive binary analysis workflow orchestrator"""

    def __init__(self):
        self.binary_engine = EnhancedBinaryEngine()
        self.ml_detector = MLVulnerabilityDetector()
        self.results = {}
        self.start_time = datetime.now()

    async def initialize(self):
        """Initialize all analysis components"""
        logger.info("Initializing binary analysis workflow...")

        try:
            # Initialize ML models
            await self.ml_detector.initialize_models()
            logger.info("✅ ML vulnerability detector initialized")

            logger.info("✅ Binary analysis workflow ready")

        except Exception as e:
            logger.error(f"❌ Workflow initialization failed: {e}")
            raise

    async def analyze_binary_comprehensive(
        self,
        binary_path: str,
        analysis_type: str = "full",
        enable_dynamic: bool = False,
        enable_ml: bool = True,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive binary analysis

        Args:
            binary_path: Path to binary file
            analysis_type: Type of analysis (quick, standard, full, custom)
            enable_dynamic: Enable dynamic analysis
            enable_ml: Enable ML-based analysis
            output_format: Output format (json, xml, html, pdf)
        """
        logger.info(f"Starting comprehensive analysis of: {binary_path}")

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        results = {
            'workflow_info': {
                'version': '3.0',
                'start_time': self.start_time.isoformat(),
                'analysis_type': analysis_type,
                'binary_path': binary_path,
                'file_size': os.path.getsize(binary_path),
                'dynamic_analysis': enable_dynamic,
                'ml_analysis': enable_ml
            },
            'metadata': {},
            'static_analysis': {},
            'dynamic_analysis': {},
            'ml_analysis': {},
            'vulnerability_assessment': {},
            'recommendations': [],
            'timeline': []
        }

        try:
            # Phase 1: Binary Metadata Extraction
            phase_start = datetime.now()
            logger.info("📊 Phase 1: Extracting binary metadata...")

            metadata = await self.binary_engine._extract_metadata(binary_path)
            results['metadata'] = {
                'format': str(metadata.format),
                'architecture': str(metadata.architecture),
                'entry_point': metadata.entry_point,
                'file_size': metadata.file_size,
                'entropy': metadata.entropy,
                'packed': metadata.packed,
                'signed': metadata.signed,
                'debug_info': metadata.debug_info,
                'stripped': metadata.stripped,
                'sections': metadata.sections[:10],  # First 10 sections
                'imports': metadata.imports[:50],    # First 50 imports
                'exports': metadata.exports[:50],    # First 50 exports
                'strings': metadata.strings[:100]    # First 100 strings
            }

            phase_duration = (datetime.now() - phase_start).total_seconds()
            results['timeline'].append({
                'phase': 'metadata_extraction',
                'duration_seconds': phase_duration,
                'status': 'completed'
            })

            logger.info(f"✅ Metadata extraction completed in {phase_duration:.2f}s")

            # Phase 2: Static Analysis
            if analysis_type in ['standard', 'full']:
                phase_start = datetime.now()
                logger.info("🔍 Phase 2: Performing static analysis...")

                static_results = await self.binary_engine._comprehensive_static_analysis(
                    binary_path, metadata
                )
                results['static_analysis'] = static_results

                phase_duration = (datetime.now() - phase_start).total_seconds()
                results['timeline'].append({
                    'phase': 'static_analysis',
                    'duration_seconds': phase_duration,
                    'status': 'completed'
                })

                logger.info(f"✅ Static analysis completed in {phase_duration:.2f}s")

            # Phase 3: Dynamic Analysis (if enabled)
            if enable_dynamic and analysis_type == 'full':
                phase_start = datetime.now()
                logger.info("🏃 Phase 3: Performing dynamic analysis...")

                try:
                    dynamic_results = await self.binary_engine._dynamic_analysis(
                        binary_path, metadata
                    )
                    results['dynamic_analysis'] = dynamic_results

                    phase_duration = (datetime.now() - phase_start).total_seconds()
                    results['timeline'].append({
                        'phase': 'dynamic_analysis',
                        'duration_seconds': phase_duration,
                        'status': 'completed'
                    })

                    logger.info(f"✅ Dynamic analysis completed in {phase_duration:.2f}s")

                except Exception as e:
                    logger.warning(f"⚠️ Dynamic analysis failed: {e}")
                    results['timeline'].append({
                        'phase': 'dynamic_analysis',
                        'duration_seconds': 0,
                        'status': 'failed',
                        'error': str(e)
                    })

            # Phase 4: ML-Based Vulnerability Analysis
            if enable_ml:
                phase_start = datetime.now()
                logger.info("🤖 Phase 4: Performing ML vulnerability analysis...")

                try:
                    ml_results = await self.ml_detector.analyze_binary_file(binary_path)
                    results['ml_analysis'] = ml_results

                    phase_duration = (datetime.now() - phase_start).total_seconds()
                    results['timeline'].append({
                        'phase': 'ml_analysis',
                        'duration_seconds': phase_duration,
                        'status': 'completed'
                    })

                    logger.info(f"✅ ML analysis completed in {phase_duration:.2f}s")

                except Exception as e:
                    logger.warning(f"⚠️ ML analysis failed: {e}")
                    results['timeline'].append({
                        'phase': 'ml_analysis',
                        'duration_seconds': 0,
                        'status': 'failed',
                        'error': str(e)
                    })

            # Phase 5: Vulnerability Assessment
            phase_start = datetime.now()
            logger.info("🛡️ Phase 5: Performing vulnerability assessment...")

            vuln_assessment = await self._perform_vulnerability_assessment(results)
            results['vulnerability_assessment'] = vuln_assessment

            phase_duration = (datetime.now() - phase_start).total_seconds()
            results['timeline'].append({
                'phase': 'vulnerability_assessment',
                'duration_seconds': phase_duration,
                'status': 'completed'
            })

            logger.info(f"✅ Vulnerability assessment completed in {phase_duration:.2f}s")

            # Phase 6: Generate Recommendations
            recommendations = await self._generate_recommendations(results)
            results['recommendations'] = recommendations

            # Final results
            total_duration = (datetime.now() - self.start_time).total_seconds()
            results['workflow_info']['total_duration_seconds'] = total_duration
            results['workflow_info']['end_time'] = datetime.now().isoformat()

            logger.info(f"🎉 Binary analysis workflow completed in {total_duration:.2f}s")

            return results

        except Exception as e:
            logger.error(f"❌ Binary analysis workflow failed: {e}")
            results['workflow_info']['error'] = str(e)
            results['workflow_info']['status'] = 'failed'
            return results

    async def _perform_vulnerability_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive vulnerability assessment"""

        assessment = {
            'overall_risk_score': 0.0,
            'risk_level': 'LOW',
            'critical_findings': [],
            'security_features': {},
            'compliance_status': {},
            'owasp_top10_mapping': [],
            'cwe_mappings': []
        }

        try:
            # Calculate overall risk score
            risk_factors = []

            # Factor 1: File characteristics
            metadata = results.get('metadata', {})
            if metadata.get('packed', False):
                risk_factors.append(('packed_binary', 0.3))
            if metadata.get('entropy', 0) > 7.5:
                risk_factors.append(('high_entropy', 0.2))
            if not metadata.get('signed', False):
                risk_factors.append(('unsigned_binary', 0.1))

            # Factor 2: ML analysis results
            ml_analysis = results.get('ml_analysis', {})
            ml_score = ml_analysis.get('vulnerability_score', 0)
            if ml_score > 0:
                risk_factors.append(('ml_vulnerabilities', ml_score * 0.4))

            # Factor 3: Static analysis results
            static_analysis = results.get('static_analysis', {})
            if static_analysis.get('dangerous_functions'):
                risk_factors.append(('dangerous_functions', 0.2))
            if static_analysis.get('hardcoded_secrets'):
                risk_factors.append(('hardcoded_secrets', 0.3))

            # Calculate final score
            total_risk = sum(score for _, score in risk_factors)
            assessment['overall_risk_score'] = min(total_risk, 1.0)

            # Determine risk level
            if assessment['overall_risk_score'] >= 0.8:
                assessment['risk_level'] = 'CRITICAL'
            elif assessment['overall_risk_score'] >= 0.6:
                assessment['risk_level'] = 'HIGH'
            elif assessment['overall_risk_score'] >= 0.4:
                assessment['risk_level'] = 'MEDIUM'
            else:
                assessment['risk_level'] = 'LOW'

            # Extract critical findings
            if ml_analysis.get('findings'):
                critical_findings = [
                    finding for finding in ml_analysis['findings']
                    if finding.get('severity') in ['CRITICAL', 'HIGH']
                ]
                assessment['critical_findings'] = critical_findings[:10]  # Top 10

            # Security features analysis
            assessment['security_features'] = {
                'pie_enabled': static_analysis.get('pie_enabled', False),
                'nx_enabled': static_analysis.get('nx_enabled', False),
                'stack_canary': static_analysis.get('stack_canary', False),
                'relro_enabled': static_analysis.get('relro_enabled', False),
                'fortify_source': static_analysis.get('fortify_source', False)
            }

        except Exception as e:
            logger.error(f"Vulnerability assessment failed: {e}")
            assessment['error'] = str(e)

        return assessment

    async def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis results"""

        recommendations = []

        try:
            # Recommendations based on vulnerability assessment
            vuln_assessment = results.get('vulnerability_assessment', {})
            risk_level = vuln_assessment.get('risk_level', 'LOW')

            if risk_level in ['CRITICAL', 'HIGH']:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'security',
                    'title': 'Immediate Security Review Required',
                    'description': 'This binary exhibits high-risk characteristics and requires immediate security review.',
                    'action_items': [
                        'Conduct manual security code review',
                        'Implement additional security controls',
                        'Consider quarantine until review complete'
                    ]
                })

            # Recommendations based on missing security features
            security_features = vuln_assessment.get('security_features', {})

            if not security_features.get('pie_enabled', False):
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'compilation',
                    'title': 'Enable Position Independent Executable (PIE)',
                    'description': 'Binary should be compiled with PIE to prevent certain exploits.',
                    'action_items': ['Recompile with -fPIE flag']
                })

            if not security_features.get('stack_canary', False):
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'compilation',
                    'title': 'Enable Stack Protection',
                    'description': 'Binary should use stack canaries to detect buffer overflows.',
                    'action_items': ['Compile with -fstack-protector-strong']
                })

            # Recommendations based on ML findings
            ml_analysis = results.get('ml_analysis', {})
            if ml_analysis.get('findings'):
                for finding in ml_analysis['findings'][:5]:  # Top 5 findings
                    if finding.get('severity') in ['CRITICAL', 'HIGH']:
                        recommendations.append({
                            'priority': finding.get('severity'),
                            'category': 'vulnerability',
                            'title': f"Address {finding.get('vulnerability_type', 'Unknown')}",
                            'description': finding.get('description', ''),
                            'action_items': [finding.get('recommendation', '')]
                        })

            # General recommendations
            recommendations.append({
                'priority': 'LOW',
                'category': 'monitoring',
                'title': 'Implement Runtime Monitoring',
                'description': 'Deploy runtime monitoring to detect suspicious behavior.',
                'action_items': [
                    'Enable application monitoring',
                    'Set up security alerting',
                    'Implement anomaly detection'
                ]
            })

        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")

        return recommendations

    async def save_results(self, results: Dict[str, Any], output_path: str, format_type: str = "json"):
        """Save analysis results to file"""

        try:
            if format_type.lower() == "json":
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2, default=str)

            elif format_type.lower() == "html":
                html_content = await self._generate_html_report(results)
                with open(output_path, 'w') as f:
                    f.write(html_content)

            logger.info(f"✅ Results saved to: {output_path}")

        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            raise

    async def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report from analysis results"""

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>QuantumSentinel Binary Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                .critical { background: #e74c3c; color: white; }
                .high { background: #e67e22; color: white; }
                .medium { background: #f39c12; color: white; }
                .low { background: #27ae60; color: white; }
                .timeline { display: flex; flex-direction: column; }
                .phase { margin: 5px 0; padding: 10px; background: #ecf0f1; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>QuantumSentinel Binary Analysis Report</h1>
                <p>Generated: {timestamp}</p>
                <p>Binary: {binary_path}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <p><strong>Risk Level:</strong> <span class="{risk_class}">{risk_level}</span></p>
                <p><strong>Overall Risk Score:</strong> {risk_score:.2f}</p>
                <p><strong>Analysis Duration:</strong> {duration:.2f} seconds</p>
            </div>

            <div class="section">
                <h2>Critical Findings</h2>
                {critical_findings}
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                {recommendations}
            </div>

            <div class="section">
                <h2>Analysis Timeline</h2>
                <div class="timeline">
                    {timeline}
                </div>
            </div>
        </body>
        </html>
        """

        # Extract data for template
        workflow_info = results.get('workflow_info', {})
        vuln_assessment = results.get('vulnerability_assessment', {})

        risk_level = vuln_assessment.get('risk_level', 'LOW')
        risk_score = vuln_assessment.get('overall_risk_score', 0.0)

        # Generate sections
        critical_findings_html = ""
        for finding in vuln_assessment.get('critical_findings', [])[:5]:
            critical_findings_html += f"<div class='finding'><strong>{finding.get('title', 'Unknown')}</strong>: {finding.get('description', '')}</div>"

        recommendations_html = ""
        for rec in results.get('recommendations', [])[:5]:
            recommendations_html += f"<div class='recommendation'><strong>{rec.get('title', 'Unknown')}</strong>: {rec.get('description', '')}</div>"

        timeline_html = ""
        for phase in results.get('timeline', []):
            timeline_html += f"<div class='phase'><strong>{phase.get('phase', 'Unknown')}</strong>: {phase.get('duration_seconds', 0):.2f}s ({phase.get('status', 'unknown')})</div>"

        return html_template.format(
            timestamp=datetime.now().isoformat(),
            binary_path=workflow_info.get('binary_path', 'Unknown'),
            risk_level=risk_level,
            risk_class=risk_level.lower(),
            risk_score=risk_score,
            duration=workflow_info.get('total_duration_seconds', 0),
            critical_findings=critical_findings_html,
            recommendations=recommendations_html,
            timeline=timeline_html
        )

async def main():
    """Main workflow execution"""
    parser = argparse.ArgumentParser(description='QuantumSentinel Binary Analysis Workflow')
    parser.add_argument('binary_path', help='Path to binary file to analyze')
    parser.add_argument('--analysis-type', choices=['quick', 'standard', 'full'],
                       default='standard', help='Type of analysis to perform')
    parser.add_argument('--enable-dynamic', action='store_true',
                       help='Enable dynamic analysis (requires sandboxed environment)')
    parser.add_argument('--disable-ml', action='store_true',
                       help='Disable ML-based analysis')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'html'], default='json',
                       help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize workflow
    workflow = BinaryAnalysisWorkflow()
    await workflow.initialize()

    try:
        # Run analysis
        results = await workflow.analyze_binary_comprehensive(
            binary_path=args.binary_path,
            analysis_type=args.analysis_type,
            enable_dynamic=args.enable_dynamic,
            enable_ml=not args.disable_ml,
            output_format=args.format
        )

        # Save results
        if args.output:
            await workflow.save_results(results, args.output, args.format)
        else:
            # Print to stdout
            if args.format == 'json':
                print(json.dumps(results, indent=2, default=str))
            else:
                html_content = await workflow._generate_html_report(results)
                print(html_content)

        # Exit with appropriate code
        risk_level = results.get('vulnerability_assessment', {}).get('risk_level', 'LOW')
        if risk_level == 'CRITICAL':
            sys.exit(2)
        elif risk_level == 'HIGH':
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        logger.error(f"Workflow execution failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    asyncio.run(main())