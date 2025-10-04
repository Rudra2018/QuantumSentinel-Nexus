#!/usr/bin/env python3
"""
🚀 Test Unified Advanced Workflow
Quick test of the unified advanced security analysis platform
"""

import os
import sys
from unified_advanced_workflow import UnifiedAdvancedWorkflow

def test_unified_workflow():
    """Test the unified workflow with minimal simulation"""

    # File path
    file_path = "/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/uploads/eeba765f-7537-4345-8435-1374681db983_H4D.apk"

    if not os.path.exists(file_path):
        print(f"❌ Test file not found: {file_path}")
        return

    print("🚀 TESTING UNIFIED ADVANCED WORKFLOW")
    print("=" * 50)
    print(f"📁 Target: {os.path.basename(file_path)}")

    # Initialize workflow
    workflow = UnifiedAdvancedWorkflow()

    # Override simulation timing for quick test
    workflow.advanced_engines._simulate_analysis_time = lambda duration, name: print(f"      ✅ {name}: COMPLETED")

    try:
        # Run analysis
        results = workflow.run_complete_analysis(file_path)

        print(f"\n🎉 TEST COMPLETE!")
        print(f"🎯 Risk Level: {results['unified_summary']['unified_risk_level']}")
        print(f"🔍 Total Findings: {results['unified_summary']['total_findings']}")
        print(f"🔧 Engines Executed: {results['unified_summary']['total_engines_executed']}")
        print(f"📊 Report: {results['report_path']}")

        # Show execution phases
        print(f"\n📈 EXECUTION PHASES:")
        for phase in results['execution_phases']:
            print(f"  ✅ {phase['phase']}: {phase['status']} ({phase['duration_minutes']:.1f}m)")

        return True

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_unified_workflow()
    sys.exit(0 if success else 1)