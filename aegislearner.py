#!/usr/bin/env python3
"""
🛡️ AegisLearner-AI: Intelligent Security Testing Platform

Advanced AI-driven security assessment platform with comprehensive learning framework.
Continuously adapts and improves security testing strategies through machine learning.

Author: AegisLearner-AI Team
License: MIT
"""

import asyncio
import argparse
import json
import logging
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.intelligent_orchestrator import intelligent_orchestrator
from shared.learning.adaptive_learning_system import AdaptiveLearningSystem
from shared.learning.learning_integration import learning_integration

class AegisLearnerAI:
    """
    🛡️ AegisLearner-AI: Intelligent Security Testing Platform

    Main application class that provides comprehensive security testing
    with AI-driven learning and continuous improvement capabilities.
    """

    def __init__(self):
        self.logger = self._setup_logging()
        self.orchestrator = intelligent_orchestrator
        self.learning_system = AdaptiveLearningSystem()
        self.learning_integration = learning_integration

        # Ensure required directories exist
        self._initialize_directories()

        self.logger.info("🚀 AegisLearner-AI Platform initialized")

    def _setup_logging(self):
        """Setup comprehensive logging system"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f'aegislearner_ai_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)

    def _initialize_directories(self):
        """Initialize required directories"""
        dirs = ['logs', 'reports', 'data', 'configs']
        for dir_name in dirs:
            Path(dir_name).mkdir(exist_ok=True)

    async def run_assessment(self, target: str, assessment_type: str = 'comprehensive',
                           config_file: str = None, output_format: str = 'json') -> Dict[str, Any]:
        """
        Run a complete security assessment with AI learning

        Args:
            target: Target domain/IP for assessment
            assessment_type: Type of assessment (comprehensive, focused, compliance)
            config_file: Optional configuration file path
            output_format: Output format (json, html, pdf)

        Returns:
            Complete assessment results with learning insights
        """

        self.logger.info(f"🎯 Starting {assessment_type} assessment for {target}")

        # Validate target
        if not target or target.strip() == '':
            raise ValueError("Target cannot be empty")

        # Build target configuration
        target_config = {
            'target': target.strip(),
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'learning_enabled': True,
            'output_format': output_format
        }

        # Load additional config if provided
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    additional_config = json.load(f)
                    target_config.update(additional_config)
                self.logger.info(f"📝 Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load config file {config_file}: {e}")

        try:
            # Execute intelligent assessment
            self.logger.info("🧠 Executing AI-enhanced security assessment")
            assessment_results = await self.orchestrator.execute_intelligent_assessment(
                target_config, assessment_type
            )

            # Save results
            results_file = self._save_assessment_results(
                assessment_results, target, output_format
            )

            self.logger.info(f"✅ Assessment completed. Results saved to {results_file}")

            return assessment_results

        except Exception as e:
            self.logger.error(f"❌ Assessment failed: {e}")
            raise

    def _save_assessment_results(self, results: Dict[str, Any], target: str,
                               output_format: str) -> str:
        """Save assessment results in specified format"""

        # Create results directory
        results_dir = Path('reports')
        results_dir.mkdir(exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('.', '_').replace(':', '_').replace('/', '_')

        if output_format.lower() == 'json':
            filename = f"assessment_{safe_target}_{timestamp}.json"
            filepath = results_dir / filename

            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)

        elif output_format.lower() == 'html':
            filename = f"assessment_{safe_target}_{timestamp}.html"
            filepath = results_dir / filename

            html_content = self._generate_html_report(results)
            with open(filepath, 'w') as f:
                f.write(html_content)

        else:
            # Default to JSON
            filename = f"assessment_{safe_target}_{timestamp}.json"
            filepath = results_dir / filename

            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)

        return str(filepath)

    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report from results"""
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AegisLearner-AI Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .vulnerability {{ background-color: #fff5f5; border-left: 4px solid #e53e3e; padding: 10px; margin: 10px 0; }}
        .success {{ color: #38a169; }}
        .warning {{ color: #d69e2e; }}
        .error {{ color: #e53e3e; }}
        .info {{ color: #3182ce; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AegisLearner-AI Security Assessment Report</h1>
        <p>Target: {results.get('target', {}).get('target', 'Unknown')}</p>
        <p>Assessment Type: {results.get('assessment_type', 'Unknown')}</p>
        <p>Generated: {results.get('timestamp', 'Unknown')}</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <p><strong>Overall Success:</strong> <span class="{'success' if results.get('overall_results', {}).get('overall_success', False) else 'error'}">{results.get('overall_results', {}).get('overall_success', 'Unknown')}</span></p>
        <p><strong>Total Findings:</strong> {results.get('overall_results', {}).get('total_findings', 0)}</p>
        <p><strong>Total Vulnerabilities:</strong> {results.get('overall_results', {}).get('total_vulnerabilities', 0)}</p>
        <p><strong>Assessment Quality:</strong> {results.get('overall_results', {}).get('assessment_quality', 'Unknown')}</p>
    </div>

    <div class="section">
        <h2>🔍 Assessment Phases</h2>
        {self._generate_phases_html(results.get('phases', {}))}
    </div>

    <div class="section">
        <h2>🧠 Learning Insights</h2>
        <pre>{json.dumps(results.get('learning_insights', {}), indent=2)}</pre>
    </div>

    <div class="section">
        <h2>⚡ Performance Metrics</h2>
        <pre>{json.dumps(results.get('performance_metrics', {}), indent=2)}</pre>
    </div>
</body>
</html>
        """
        return html_template

    def _generate_phases_html(self, phases: Dict[str, Any]) -> str:
        """Generate HTML for assessment phases"""
        html_content = ""

        for phase_name, phase_data in phases.items():
            status_class = "success" if phase_data.get('success', False) else "error"
            html_content += f"""
            <div class="section">
                <h3>{phase_name.replace('_', ' ').title()}</h3>
                <p><strong>Status:</strong> <span class="{status_class}">{phase_data.get('success', 'Unknown')}</span></p>
                <p><strong>Started:</strong> {phase_data.get('started_at', 'Unknown')}</p>
                <p><strong>Completed:</strong> {phase_data.get('completed_at', 'Unknown')}</p>
            </div>
            """

        return html_content

    async def continuous_learning_mode(self, target: str, intervals: int = 24,
                                     assessment_interval: int = 3600):
        """
        Run continuous learning mode with periodic assessments

        Args:
            target: Target for continuous monitoring
            intervals: Number of assessment intervals to run
            assessment_interval: Seconds between assessments
        """

        self.logger.info(f"🔄 Starting continuous learning mode for {target}")
        self.logger.info(f"Running {intervals} intervals every {assessment_interval/3600:.1f} hours")

        for i in range(intervals):
            try:
                self.logger.info(f"🔍 Running assessment {i+1}/{intervals}")

                # Run assessment
                results = await self.run_assessment(target, 'focused')

                # Analyze learning progress
                learning_summary = await self.learning_integration.generate_learning_summary()

                self.logger.info(f"📈 Learning progress: {learning_summary.get('summary', {})}")

                # Wait for next interval (except last one)
                if i < intervals - 1:
                    self.logger.info(f"⏳ Waiting {assessment_interval/3600:.1f} hours for next assessment")
                    await asyncio.sleep(assessment_interval)

            except Exception as e:
                self.logger.error(f"❌ Continuous learning iteration {i+1} failed: {e}")

        self.logger.info("🎯 Continuous learning mode completed")

    async def system_optimization(self) -> Dict[str, Any]:
        """Optimize system performance based on learning"""
        self.logger.info("⚡ Optimizing system performance based on learning")

        optimization_results = await self.orchestrator.optimize_system_performance()

        self.logger.info("✅ System optimization completed")
        return optimization_results

    async def learning_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive learning analysis"""
        self.logger.info("🧠 Generating learning analysis")

        analysis = {
            'timestamp': datetime.now().isoformat(),
            'learning_summary': await self.learning_integration.generate_learning_summary(),
            'system_status': await self.orchestrator.get_system_status(),
            'performance_insights': {}
        }

        # Get insights for each agent type
        agent_types = ['reconnaissance', 'vulnerability_analysis', 'security_testing', 'reporting']
        for agent_type in agent_types:
            insights = await self.learning_integration.get_performance_insights(agent_type)
            analysis['performance_insights'][agent_type] = insights

        return analysis

    def display_banner(self):
        """Display AegisLearner-AI banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🛡️ AEGISLEARNER-AI SECURITY PLATFORM 🛡️                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  🔹 AI-Driven Security Testing with Continuous Learning                     ║
║  🔹 Advanced Vulnerability Assessment & Penetration Testing                 ║
║  🔹 OWASP, MBE, and Professional Reporting Standards                        ║
║  🔹 Intelligent Agent Coordination & Optimization                           ║
║  🔹 Real-time Learning & Performance Adaptation                             ║
║                                                                              ║
║  🚀 Revolutionizing Cybersecurity Through Artificial Intelligence           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    async def interactive_mode(self):
        """Run interactive mode for manual control"""
        self.display_banner()

        print("\n🎛️  Interactive Mode - Available Commands:")
        print("   1. Run Security Assessment")
        print("   2. Continuous Learning Mode")
        print("   3. System Optimization")
        print("   4. Learning Analysis")
        print("   5. System Status")
        print("   6. Help & Documentation")
        print("   7. Exit")

        while True:
            try:
                choice = input("\n👉 Select option (1-7): ").strip()

                if choice == '1':
                    target = input("🎯 Enter target domain/IP: ").strip()
                    if target:
                        assessment_type = input("📋 Assessment type (comprehensive/focused/compliance) [comprehensive]: ").strip() or 'comprehensive'
                        output_format = input("📄 Output format (json/html) [json]: ").strip() or 'json'
                        await self.run_assessment(target, assessment_type, output_format=output_format)
                    else:
                        print("❌ Invalid target")

                elif choice == '2':
                    target = input("🎯 Enter target for continuous monitoring: ").strip()
                    if target:
                        intervals = int(input("🔢 Number of intervals (default 24): ") or "24")
                        interval_hours = float(input("⏱️  Hours between assessments (default 1): ") or "1")
                        await self.continuous_learning_mode(target, intervals, int(interval_hours * 3600))
                    else:
                        print("❌ Invalid target")

                elif choice == '3':
                    results = await self.system_optimization()
                    print(f"⚡ Optimization results:")
                    print(json.dumps(results, indent=2, default=str))

                elif choice == '4':
                    analysis = await self.learning_analysis()
                    print(f"🧠 Learning analysis:")
                    print(json.dumps(analysis, indent=2, default=str))

                elif choice == '5':
                    status = await self.orchestrator.get_system_status()
                    print(f"📊 System status:")
                    print(json.dumps(status, indent=2, default=str))

                elif choice == '6':
                    self._show_help()

                elif choice == '7':
                    print("👋 Thank you for using AegisLearner-AI!")
                    break

                else:
                    print("❌ Invalid option. Please select 1-7.")

            except KeyboardInterrupt:
                print("\n\n👋 Thank you for using AegisLearner-AI!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def _show_help(self):
        """Display help information"""
        help_text = """
🛡️ AegisLearner-AI Help & Documentation

ASSESSMENT TYPES:
• comprehensive: Full security evaluation with all testing phases
• focused: Targeted testing for specific vulnerabilities
• compliance: Standards-based evaluation (OWASP, PCI DSS, etc.)

OUTPUT FORMATS:
• json: Machine-readable JSON format
• html: Human-readable HTML report

FEATURES:
• AI-driven vulnerability detection
• Continuous learning and improvement
• Professional reporting standards
• Real-time performance optimization
• Multi-agent coordination

For detailed documentation, visit: https://github.com/YourRepo/AegisLearner-AI
        """
        print(help_text)

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🛡️ AegisLearner-AI: Intelligent Security Testing Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aegislearner.py --interactive                    # Interactive mode
  python aegislearner.py -t example.com                   # Basic assessment
  python aegislearner.py -t example.com -a comprehensive  # Full assessment
  python aegislearner.py -t example.com --continuous      # Continuous monitoring
  python aegislearner.py --optimize                       # System optimization
        """
    )

    parser.add_argument('--target', '-t',
                       help='Target domain/IP for assessment')
    parser.add_argument('--assessment-type', '-a',
                       choices=['comprehensive', 'focused', 'compliance'],
                       default='comprehensive',
                       help='Type of assessment to run')
    parser.add_argument('--config', '-c',
                       help='Configuration file path')
    parser.add_argument('--output-format', '-f',
                       choices=['json', 'html'],
                       default='json',
                       help='Output format for reports')
    parser.add_argument('--continuous',
                       action='store_true',
                       help='Run in continuous learning mode')
    parser.add_argument('--intervals', '-i',
                       type=int, default=24,
                       help='Number of intervals for continuous mode')
    parser.add_argument('--interval-hours',
                       type=float, default=1.0,
                       help='Hours between assessments in continuous mode')
    parser.add_argument('--optimize',
                       action='store_true',
                       help='Run system optimization')
    parser.add_argument('--analyze',
                       action='store_true',
                       help='Run learning analysis')
    parser.add_argument('--interactive',
                       action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--version', '-v',
                       action='version',
                       version='AegisLearner-AI v1.0.0')

    args = parser.parse_args()

    # Initialize platform
    platform = AegisLearnerAI()

    try:
        if args.interactive or (not args.target and not args.optimize and not args.analyze):
            await platform.interactive_mode()

        elif args.target:
            if args.continuous:
                await platform.continuous_learning_mode(
                    args.target,
                    args.intervals,
                    int(args.interval_hours * 3600)
                )
            else:
                await platform.run_assessment(
                    args.target,
                    args.assessment_type,
                    args.config,
                    args.output_format
                )

        elif args.optimize:
            results = await platform.system_optimization()
            print(json.dumps(results, indent=2, default=str))

        elif args.analyze:
            analysis = await platform.learning_analysis()
            print(json.dumps(analysis, indent=2, default=str))

    except KeyboardInterrupt:
        platform.logger.info("👋 AegisLearner-AI shutdown by user")
    except Exception as e:
        platform.logger.error(f"❌ AegisLearner-AI error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())