#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Huntr.com Bug Bounty Runner
Specialized runner for AI/ML security testing on Huntr platform
"""

import asyncio
import argparse
import logging
import json
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Import QuantumSentinel components
from orchestration.ultimate_orchestrator import UltimateOrchestrator, OrchestrationConfig

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HuntrBountyRunner:
    """Specialized runner for Huntr.com AI/ML security testing"""

    def __init__(self, config_path: str = "configs/huntr_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_huntr_config()
        self.orchestrator = UltimateOrchestrator()

    def _load_huntr_config(self) -> Dict[str, Any]:
        """Load Huntr-specific configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            logger.error(f"Huntr config file not found: {self.config_path}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Huntr testing"""
        return {
            "platform_config": {"name": "huntr", "type": "ai_ml_security"},
            "scan_profiles": {
                "ai_ml_basic": {"scan_depth": "basic", "timeout_minutes": 30},
                "ai_ml_comprehensive": {"scan_depth": "comprehensive", "timeout_minutes": 120}
            }
        }

    async def test_ai_ml_framework(self, framework_name: str, target_path: str,
                                 scan_profile: str = "ai_ml_comprehensive") -> Dict[str, Any]:
        """Test an AI/ML framework for security vulnerabilities"""
        logger.info(f"🤖 Starting AI/ML security test for {framework_name}")
        logger.info(f"🎯 Target: {target_path}")
        logger.info(f"📊 Profile: {scan_profile}")

        try:
            # Get scan profile configuration
            profile_config = self.config["scan_profiles"].get(scan_profile, {})

            # Create orchestration configuration for AI/ML testing
            config = OrchestrationConfig(
                target=target_path,
                target_type="source_code",  # Most AI/ML targets are source code
                scan_depth=profile_config.get("scan_depth", "comprehensive"),
                enable_ml_detection=True,  # Enable ML detection for AI/ML targets
                enable_evidence_collection=True,
                enable_bug_bounty_submission=False,  # Manual submission to Huntr
                bug_bounty_platform="huntr",
                output_format=["json", "html", "pdf"],
                timeout_minutes=profile_config.get("timeout_minutes", 120),
                custom_payloads=self._get_ai_ml_payloads(framework_name),
                include_tests=self._get_ai_ml_tests(framework_name)
            )

            # Execute assessment
            result = await self.orchestrator.execute_complete_assessment(config)

            # Post-process for Huntr-specific analysis
            huntr_analysis = await self._analyze_for_huntr(result, framework_name)

            return {
                "framework": framework_name,
                "assessment_result": result,
                "huntr_analysis": huntr_analysis,
                "submission_ready": huntr_analysis["high_value_findings"] > 0
            }

        except Exception as e:
            logger.error(f"❌ Error testing {framework_name}: {e}")
            return {"error": str(e), "framework": framework_name}

    def _get_ai_ml_payloads(self, framework_name: str) -> str:
        """Get AI/ML specific payloads for testing"""
        payloads = {
            "pytorch": [
                "torch.load exploitation",
                "pickle deserialization",
                "model poisoning",
                "unsafe serialization"
            ],
            "tensorflow": [
                "SavedModel manipulation",
                "TensorFlow Serving attacks",
                "Graph manipulation",
                "Operation injection"
            ],
            "huggingface": [
                "Model hub exploitation",
                "Tokenizer attacks",
                "Pipeline injection",
                "Hub API abuse"
            ],
            "scikit-learn": [
                "joblib exploitation",
                "pickle vulnerabilities",
                "estimator manipulation"
            ],
            "default": [
                "Dependency confusion",
                "Code injection",
                "Path traversal",
                "Unsafe deserialization"
            ]
        }

        framework_payloads = payloads.get(framework_name.lower(), payloads["default"])
        return "\n".join(framework_payloads)

    def _get_ai_ml_tests(self, framework_name: str) -> List[str]:
        """Get AI/ML specific tests"""
        common_tests = [
            "dependency_security_scan",
            "code_injection_testing",
            "deserialization_testing",
            "api_security_testing"
        ]

        framework_specific = {
            "pytorch": ["torch_load_testing", "pickle_exploitation", "model_poisoning"],
            "tensorflow": ["savedmodel_testing", "serving_api_testing", "graph_manipulation"],
            "huggingface": ["model_hub_testing", "tokenizer_testing", "pipeline_injection"],
            "jupyter": ["notebook_injection", "kernel_exploitation", "extension_testing"],
            "mlflow": ["model_registry_testing", "tracking_api_testing", "artifact_manipulation"]
        }

        specific_tests = framework_specific.get(framework_name.lower(), [])
        return common_tests + specific_tests

    async def _analyze_for_huntr(self, result: Any, framework_name: str) -> Dict[str, Any]:
        """Analyze results specifically for Huntr submission"""
        analysis = {
            "framework": framework_name,
            "total_findings": len(result.vulnerabilities_found),
            "high_value_findings": 0,
            "ai_ml_specific_vulns": [],
            "bounty_potential": "low",
            "submission_priority": [],
            "huntr_categories": []
        }

        # Categorize vulnerabilities for Huntr
        for vuln in result.vulnerabilities_found:
            vuln_type = vuln.get("vulnerability_type", "").lower()
            severity = vuln.get("severity", "").lower()

            # Check for high-value AI/ML vulnerabilities
            high_value_types = [
                "pickle_deserialization", "unsafe_deserialization", "code_injection",
                "remote_code_execution", "model_poisoning", "privilege_escalation"
            ]

            if any(hvt in vuln_type for hvt in high_value_types):
                analysis["high_value_findings"] += 1
                analysis["ai_ml_specific_vulns"].append({
                    "type": vuln_type,
                    "severity": severity,
                    "title": vuln.get("title", "Unknown"),
                    "huntr_category": self._map_to_huntr_category(vuln_type, framework_name)
                })

            if severity in ["critical", "high"]:
                analysis["submission_priority"].append(vuln)

        # Determine bounty potential
        if analysis["high_value_findings"] >= 3:
            analysis["bounty_potential"] = "high"
        elif analysis["high_value_findings"] >= 1:
            analysis["bounty_potential"] = "medium"

        # Map to Huntr categories
        analysis["huntr_categories"] = self._get_huntr_categories(framework_name)

        return analysis

    def _map_to_huntr_category(self, vuln_type: str, framework_name: str) -> str:
        """Map vulnerability type to Huntr category"""
        category_mapping = {
            "pickle": "Model File Formats",
            "deserialization": "Model File Formats",
            "torch": "ML Frameworks",
            "tensorflow": "ML Frameworks",
            "api": "Inference Systems",
            "jupyter": "Data Science Tools",
            "mlflow": "ML Ops"
        }

        for key, category in category_mapping.items():
            if key in vuln_type.lower() or key in framework_name.lower():
                return category

        return "ML Frameworks"  # Default category

    def _get_huntr_categories(self, framework_name: str) -> List[str]:
        """Get relevant Huntr categories for framework"""
        framework_categories = {
            "pytorch": ["ML Frameworks", "Model File Formats"],
            "tensorflow": ["ML Frameworks", "Model File Formats", "Inference Systems"],
            "huggingface": ["ML Frameworks", "Model File Formats"],
            "jupyter": ["Data Science Tools"],
            "mlflow": ["ML Ops", "Inference Systems"],
            "scikit-learn": ["ML Frameworks"],
            "pandas": ["Data Science Tools"],
            "numpy": ["Data Science Tools"]
        }

        return framework_categories.get(framework_name.lower(), ["ML Frameworks"])

    async def generate_huntr_report(self, assessment_result: Dict[str, Any]) -> str:
        """Generate Huntr-specific submission report"""
        framework = assessment_result["framework"]
        huntr_analysis = assessment_result["huntr_analysis"]
        result = assessment_result["assessment_result"]

        report_template = f"""
# Huntr.com Security Assessment Report

## Target Information
- **Framework**: {framework}
- **Assessment Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Total Findings**: {huntr_analysis['total_findings']}
- **High-Value Findings**: {huntr_analysis['high_value_findings']}
- **Bounty Potential**: {huntr_analysis['bounty_potential'].upper()}

## Huntr Categories
{', '.join(huntr_analysis['huntr_categories'])}

## AI/ML Specific Vulnerabilities
"""

        for vuln in huntr_analysis["ai_ml_specific_vulns"]:
            report_template += f"""
### {vuln['title']} ({vuln['severity'].upper()})
- **Type**: {vuln['type']}
- **Huntr Category**: {vuln['huntr_category']}
- **Severity**: {vuln['severity']}
"""

        report_template += f"""

## Submission Priority
{len(huntr_analysis['submission_priority'])} vulnerabilities recommended for immediate submission.

## Next Steps
1. Review high-value findings for submission readiness
2. Prepare detailed proof-of-concept for each vulnerability
3. Submit via Huntr.com platform following responsible disclosure
4. Expected bounty range: {self._estimate_bounty_range(huntr_analysis)}

---
Generated by QuantumSentinel-Nexus for Huntr.com Bug Bounty Program
Report ID: QS-HUNTR-{datetime.now().strftime('%Y%m%d-%H%M%S')}
"""

        return report_template

    def _estimate_bounty_range(self, analysis: Dict[str, Any]) -> str:
        """Estimate bounty range based on findings"""
        high_value = analysis["high_value_findings"]

        if high_value >= 3:
            return "$2000-$4000 (Multiple critical findings)"
        elif high_value >= 1:
            return "$1000-$2000 (High-value vulnerability)"
        else:
            return "$100-$500 (Standard findings)"

    def list_huntr_targets(self) -> Dict[str, List[str]]:
        """List common Huntr targets by category"""
        return {
            "Popular ML Frameworks": [
                "pytorch/pytorch",
                "tensorflow/tensorflow",
                "huggingface/transformers",
                "scikit-learn/scikit-learn",
                "keras-team/keras"
            ],
            "Model File Formats": [
                "pytorch models (*.pth)",
                "tensorflow models (*.pb, *.h5)",
                "onnx models (*.onnx)",
                "pickle files (*.pkl)",
                "safetensors (*.safetensors)"
            ],
            "Inference Systems": [
                "pytorch/serve",
                "tensorflow/serving",
                "triton-inference-server",
                "mlflow/mlflow",
                "bentoml/BentoML"
            ],
            "Data Science Tools": [
                "jupyter/notebook",
                "pandas-dev/pandas",
                "numpy/numpy",
                "matplotlib/matplotlib",
                "streamlit/streamlit"
            ],
            "ML Ops": [
                "mlflow/mlflow",
                "kubeflow/kubeflow",
                "wandb/wandb",
                "iterative/dvc"
            ]
        }

def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI parser for Huntr testing"""
    parser = argparse.ArgumentParser(
        description="QuantumSentinel-Nexus Huntr.com Bug Bounty Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test PyTorch framework
  python run_huntr_bounty.py --framework pytorch --target /path/to/pytorch

  # Test with comprehensive scan
  python run_huntr_bounty.py --framework tensorflow --target /path/to/tf --profile ai_ml_comprehensive

  # List available targets
  python run_huntr_bounty.py --list-targets

  # Test specific model file
  python run_huntr_bounty.py --framework pytorch --target model.pth --profile ai_ml_basic
        """
    )

    parser.add_argument("--framework", required=True,
                       help="Target AI/ML framework (pytorch, tensorflow, huggingface, etc.)")
    parser.add_argument("--target", required=True,
                       help="Target path (repository, model file, or application)")
    parser.add_argument("--profile", choices=["ai_ml_basic", "ai_ml_comprehensive", "ai_ml_deep"],
                       default="ai_ml_comprehensive", help="Scan profile for AI/ML testing")
    parser.add_argument("--list-targets", action="store_true",
                       help="List common Huntr targets by category")
    parser.add_argument("--config", help="Custom Huntr configuration file")
    parser.add_argument("--output-dir", default="./huntr_results",
                       help="Output directory for results")

    return parser

async def main():
    """Main entry point for Huntr testing"""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Initialize runner
    config_path = args.config or "configs/huntr_config.yaml"
    runner = HuntrBountyRunner(config_path)

    if args.list_targets:
        print("🎯 Common Huntr.com Targets by Category:")
        print("=" * 50)
        targets = runner.list_huntr_targets()
        for category, target_list in targets.items():
            print(f"\n📂 {category}:")
            for target in target_list:
                print(f"  • {target}")
        return

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    try:
        print(f"🚀 Starting Huntr.com security assessment...")
        print(f"🎯 Framework: {args.framework}")
        print(f"📁 Target: {args.target}")
        print(f"⚙️ Profile: {args.profile}")

        # Run assessment
        result = await runner.test_ai_ml_framework(
            args.framework,
            args.target,
            args.profile
        )

        if "error" in result:
            print(f"❌ Assessment failed: {result['error']}")
            return

        # Generate Huntr-specific report
        huntr_report = await runner.generate_huntr_report(result)

        # Save report
        report_file = output_dir / f"huntr_report_{args.framework}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w') as f:
            f.write(huntr_report)

        # Save detailed results
        results_file = output_dir / f"detailed_results_{args.framework}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)

        # Print summary
        huntr_analysis = result["huntr_analysis"]
        print(f"\n🎉 Assessment completed!")
        print(f"📊 Total Findings: {huntr_analysis['total_findings']}")
        print(f"🎯 High-Value Findings: {huntr_analysis['high_value_findings']}")
        print(f"💰 Bounty Potential: {huntr_analysis['bounty_potential'].upper()}")
        print(f"📁 Report saved: {report_file}")
        print(f"📁 Details saved: {results_file}")

        if result["submission_ready"]:
            print(f"\n✅ Ready for Huntr submission!")
            print(f"💡 Estimated bounty: {runner._estimate_bounty_range(huntr_analysis)}")
        else:
            print(f"\n⚠️ No high-value findings for submission")

    except KeyboardInterrupt:
        print(f"\n⏹️ Assessment interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")

if __name__ == "__main__":
    asyncio.run(main())