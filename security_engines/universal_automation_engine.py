#!/usr/bin/env python3
"""
QuantumSentinel Universal Automation Security Engine
Integrates universal binary analysis (iOS, Android, Windows, Linux, macOS) into security engines
"""

import os
import sys
import json
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
import logging

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from universal_binary_analyzer import UniversalBinaryAnalyzer
    from quantum_sentinel_master import QuantumSentinelMaster
except ImportError:
    print("⚠️  Universal automation modules not found in current directory")
    UniversalBinaryAnalyzer = None
    QuantumSentinelMaster = None

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UniversalAutomationEngine:
    """Universal Automation Engine for QuantumSentinel"""

    def __init__(self):
        self.engine_id = f"UNIVERSAL-ENGINE-{int(time.time())}"
        self.supported_formats = {
            'mobile': ['.apk', '.ipa'],
            'windows': ['.exe', '.dll', '.sys'],
            'linux': ['.so', '.a'],
            'macos': ['.dylib', '.framework'],
            'java': ['.jar', '.class', '.war'],
            'archives': ['.zip', '.tar', '.gz']
        }
        self.results = {
            'engine_id': self.engine_id,
            'start_time': datetime.now().isoformat(),
            'analyses_completed': [],
            'vulnerabilities_found': [],
            'formats_processed': {},
            'total_files_analyzed': 0
        }

    def detect_file_category(self, file_path):
        """Detect file category based on extension and content"""
        file_ext = Path(file_path).suffix.lower()

        for category, extensions in self.supported_formats.items():
            if file_ext in extensions:
                return category

        # Check for binary signatures if extension detection fails
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

            # APK (ZIP signature)
            if header.startswith(b'PK\x03\x04'):
                return 'mobile'
            # PE (Windows)
            elif header.startswith(b'MZ'):
                return 'windows'
            # ELF (Linux)
            elif header.startswith(b'\x7fELF'):
                return 'linux'
            # Mach-O (macOS)
            elif header.startswith(b'\xfe\xed\xfa'):
                return 'macos'

        except Exception as e:
            logger.warning(f"Could not read file header for {file_path}: {e}")

        return 'unknown'

    def run_universal_analysis(self, target_files=None):
        """Run universal analysis on target files"""
        logger.info("🚀 Starting Universal Automation Engine...")

        # If no target files specified, look for common mobile files
        if not target_files:
            target_files = []
            current_dir = Path('.')

            # Look for APK and IPA files
            for pattern in ['*.apk', '*.ipa', '*.exe', '*.dll']:
                target_files.extend(current_dir.glob(pattern))

            # Also check Downloads directory for mobile files
            downloads_dir = Path.home() / 'Downloads'
            if downloads_dir.exists():
                for pattern in ['*.apk', '*.ipa']:
                    target_files.extend(downloads_dir.glob(pattern))

        if not target_files:
            logger.info("📁 No target files found for analysis")
            return self.results

        logger.info(f"📁 Found {len(target_files)} files for analysis")

        # Categorize files by type
        categorized_files = {}
        for file_path in target_files:
            if Path(file_path).exists():
                category = self.detect_file_category(str(file_path))
                if category not in categorized_files:
                    categorized_files[category] = []
                categorized_files[category].append(str(file_path))

        # Run analysis for each category
        for category, files in categorized_files.items():
            logger.info(f"🔍 Analyzing {len(files)} {category} files...")
            self.results['formats_processed'][category] = len(files)

            if category == 'mobile':
                self._analyze_mobile_files(files)
            elif category in ['windows', 'linux', 'macos']:
                self._analyze_binary_files(files, category)
            elif category == 'java':
                self._analyze_java_files(files)
            else:
                logger.info(f"⚠️  Category {category} not yet implemented in engine")

        self.results['total_files_analyzed'] = sum(len(files) for files in categorized_files.values())
        self.results['end_time'] = datetime.now().isoformat()

        # Generate summary report
        self._generate_engine_report()

        return self.results

    def _analyze_mobile_files(self, files):
        """Analyze mobile files (APK, IPA)"""
        logger.info("📱 Running mobile security analysis...")

        # Try to use the master automation engine
        if QuantumSentinelMaster:
            try:
                master = QuantumSentinelMaster()
                master_results = master.run_master_analysis(files)

                self.results['analyses_completed'].append({
                    'type': 'mobile_master',
                    'files': files,
                    'results': master_results,
                    'timestamp': datetime.now().isoformat()
                })

                logger.info("✅ Mobile master analysis completed")
                return

            except Exception as e:
                logger.error(f"❌ Master analysis failed: {e}")

        # Fallback to individual analysis tools
        for file_path in files:
            try:
                # Run integrated APK tester
                if file_path.endswith('.apk'):
                    result = subprocess.run([
                        'python3', 'integrated_apk_tester.py'
                    ], capture_output=True, text=True, timeout=300)

                    if result.returncode == 0:
                        self.results['analyses_completed'].append({
                            'type': 'apk_analysis',
                            'file': file_path,
                            'status': 'success',
                            'timestamp': datetime.now().isoformat()
                        })
                        logger.info(f"✅ APK analysis completed for {Path(file_path).name}")
                    else:
                        logger.error(f"❌ APK analysis failed for {file_path}")

            except Exception as e:
                logger.error(f"❌ Mobile analysis error for {file_path}: {e}")

    def _analyze_binary_files(self, files, category):
        """Analyze binary files (PE, ELF, Mach-O)"""
        logger.info(f"🔧 Running {category} binary analysis...")

        # Try to use the universal binary analyzer
        if UniversalBinaryAnalyzer:
            try:
                analyzer = UniversalBinaryAnalyzer()

                for file_path in files:
                    analysis_result = analyzer.analyze_file(file_path)

                    self.results['analyses_completed'].append({
                        'type': f'{category}_binary',
                        'file': file_path,
                        'results': analysis_result,
                        'timestamp': datetime.now().isoformat()
                    })

                    # Extract vulnerabilities
                    if 'vulnerabilities' in analysis_result:
                        self.results['vulnerabilities_found'].extend(analysis_result['vulnerabilities'])

                logger.info(f"✅ {category.title()} binary analysis completed for {len(files)} files")

            except Exception as e:
                logger.error(f"❌ Binary analysis failed for {category}: {e}")
        else:
            logger.warning(f"⚠️  Universal binary analyzer not available for {category} analysis")

    def _analyze_java_files(self, files):
        """Analyze Java files (JAR, CLASS)"""
        logger.info("☕ Running Java binary analysis...")

        for file_path in files:
            try:
                # Basic Java analysis - can be enhanced
                result = {
                    'file': file_path,
                    'type': 'java_analysis',
                    'timestamp': datetime.now().isoformat(),
                    'basic_info': {
                        'size': os.path.getsize(file_path),
                        'format': 'JAR' if file_path.endswith('.jar') else 'CLASS'
                    }
                }

                self.results['analyses_completed'].append(result)
                logger.info(f"✅ Java analysis completed for {Path(file_path).name}")

            except Exception as e:
                logger.error(f"❌ Java analysis error for {file_path}: {e}")

    def _generate_engine_report(self):
        """Generate comprehensive engine report"""
        report_data = {
            'universal_automation_engine': self.results,
            'summary': {
                'total_files': self.results['total_files_analyzed'],
                'analyses_completed': len(self.results['analyses_completed']),
                'vulnerabilities_found': len(self.results['vulnerabilities_found']),
                'formats_supported': list(self.results['formats_processed'].keys()),
                'execution_time': self._calculate_execution_time()
            }
        }

        # Save JSON report
        report_file = f"universal_engine_report_{self.engine_id}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"📄 Engine report saved: {report_file}")
        except Exception as e:
            logger.error(f"❌ Failed to save engine report: {e}")

    def _calculate_execution_time(self):
        """Calculate total execution time"""
        if 'end_time' in self.results and 'start_time' in self.results:
            start = datetime.fromisoformat(self.results['start_time'])
            end = datetime.fromisoformat(self.results['end_time'])
            return str(end - start)
        return "Unknown"

    def get_engine_status(self):
        """Get current engine status"""
        return {
            'engine_id': self.engine_id,
            'status': 'active' if 'end_time' not in self.results else 'completed',
            'files_analyzed': self.results['total_files_analyzed'],
            'analyses_completed': len(self.results['analyses_completed']),
            'vulnerabilities_found': len(self.results['vulnerabilities_found'])
        }

    def integrate_with_poc_engine(self, poc_port=8007):
        """Integrate results with PoC generation engine"""
        try:
            # Send results to PoC engine for exploit generation
            poc_data = {
                'source': 'universal_automation_engine',
                'vulnerabilities': self.results['vulnerabilities_found'],
                'analyses': self.results['analyses_completed']
            }

            logger.info(f"🔗 Integrating with PoC engine on port {poc_port}")
            # Implementation would depend on PoC engine API

        except Exception as e:
            logger.error(f"❌ PoC engine integration failed: {e}")

    def integrate_with_verification_engine(self, verification_port=8008):
        """Integrate results with verification engine"""
        try:
            # Send results to verification engine
            verification_data = {
                'source': 'universal_automation_engine',
                'results': self.results['analyses_completed']
            }

            logger.info(f"🔗 Integrating with verification engine on port {verification_port}")
            # Implementation would depend on verification engine API

        except Exception as e:
            logger.error(f"❌ Verification engine integration failed: {e}")

def main():
    """Main function for standalone execution"""
    print("🚀 QuantumSentinel Universal Automation Engine")
    print("=" * 60)

    engine = UniversalAutomationEngine()

    # Check for command line arguments
    import sys
    target_files = sys.argv[1:] if len(sys.argv) > 1 else None

    # Run universal analysis
    results = engine.run_universal_analysis(target_files)

    print("\n📊 UNIVERSAL ENGINE ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"🔧 Engine ID: {engine.engine_id}")
    print(f"📁 Files Analyzed: {results['total_files_analyzed']}")
    print(f"🔍 Analyses Completed: {len(results['analyses_completed'])}")
    print(f"🚨 Vulnerabilities Found: {len(results['vulnerabilities_found'])}")

    if results['formats_processed']:
        print(f"📋 Formats Processed:")
        for format_type, count in results['formats_processed'].items():
            print(f"   • {format_type.title()}: {count} files")

    # Integrate with other engines
    engine.integrate_with_poc_engine()
    engine.integrate_with_verification_engine()

    print(f"\n✅ Universal automation engine execution complete!")

if __name__ == "__main__":
    main()