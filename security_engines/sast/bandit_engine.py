#!/usr/bin/env python3
"""
🔍 QuantumSentinel Enhanced SAST Engine
Advanced static application security testing with Bandit integration
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger("QuantumSentinel.SASTEngine")

@dataclass
class SASTFinding:
    """SAST security finding"""
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    recommendation: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class EnhancedSASTEngine:
    """Enhanced SAST engine with Bandit integration and custom rules"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings = []

    async def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """Scan directory for security vulnerabilities"""

        results = {
            'timestamp': datetime.now().isoformat(),
            'directory_path': directory_path,
            'findings': [],
            'summary': {'total_findings': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0}
        }

        try:
            # Run Bandit scan
            bandit_results = await self._run_bandit_scan(directory_path)

            # Apply custom rules
            custom_results = await self._apply_custom_rules(directory_path)

            # Combine results
            all_findings = bandit_results + custom_results
            results['findings'] = [asdict(finding) for finding in all_findings]
            results['summary'] = self._calculate_summary(all_findings)

            logger.info(f"SAST scan completed: {len(all_findings)} findings")

        except Exception as e:
            logger.error(f"SAST scan failed: {e}")
            results['error'] = str(e)

        return results

    async def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan single file for security vulnerabilities"""

        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy file to temp directory for scanning
            temp_file = os.path.join(temp_dir, os.path.basename(file_path))
            with open(file_path, 'r') as src, open(temp_file, 'w') as dst:
                dst.write(src.read())

            return await self.scan_directory(temp_dir)

    async def _run_bandit_scan(self, target_path: str) -> List[SASTFinding]:
        """Run Bandit security scanner"""

        findings = []

        try:
            # Run bandit
            cmd = ['bandit', '-r', target_path, '-f', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.stdout:
                bandit_data = json.loads(result.stdout)

                for bandit_result in bandit_data.get('results', []):
                    finding = SASTFinding(
                        id=f"BANDIT-{len(findings)+1:03d}",
                        title=bandit_result.get('test_name', 'Unknown Issue'),
                        severity=bandit_result.get('issue_severity', 'MEDIUM'),
                        confidence=bandit_result.get('issue_confidence', 'MEDIUM'),
                        description=bandit_result.get('issue_text', 'Security issue detected'),
                        impact="Potential security vulnerability",
                        recommendation="Review and remediate security issue",
                        file_path=bandit_result.get('filename'),
                        line_number=bandit_result.get('line_number'),
                        code_snippet=bandit_result.get('code', ''),
                        cwe_id=bandit_result.get('test_id', '')
                    )
                    findings.append(finding)

        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
        except FileNotFoundError:
            logger.warning("Bandit not found, skipping Bandit scan")
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")

        return findings

    async def _apply_custom_rules(self, target_path: str) -> List[SASTFinding]:
        """Apply custom security rules"""

        findings = []

        # Scan for hardcoded secrets
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.rb', '.php')):
                    file_path = os.path.join(root, file)
                    file_findings = await self._scan_file_for_secrets(file_path)
                    findings.extend(file_findings)

        return findings

    async def _scan_file_for_secrets(self, file_path: str) -> List[SASTFinding]:
        """Scan file for hardcoded secrets"""

        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Simple regex patterns for common secrets
            import re
            patterns = [
                (r'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}', 'API Key'),
                (r'secret[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}', 'Secret Key'),
                (r'password["\s]*[:=]["\s]*["\w]{8,}', 'Password'),
            ]

            for pattern, secret_type in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    finding = SASTFinding(
                        id=f"SECRET-{len(findings)+1:03d}",
                        title=f"Hardcoded {secret_type}",
                        severity="HIGH",
                        confidence="Medium",
                        description=f"Potential hardcoded {secret_type.lower()} detected",
                        impact="Could expose sensitive credentials",
                        recommendation="Move secrets to environment variables or secure vault",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=match.group()[:100],
                        cwe_id="CWE-798"
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Failed to scan file {file_path}: {e}")

        return findings

    def _calculate_summary(self, findings: List[SASTFinding]) -> Dict[str, int]:
        """Calculate summary statistics"""

        summary = {
            'total_findings': len(findings),
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }

        for finding in findings:
            severity = finding.severity.upper()
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
            elif severity == 'HIGH':
                summary['high_count'] += 1
            elif severity == 'MEDIUM':
                summary['medium_count'] += 1
            elif severity == 'LOW':
                summary['low_count'] += 1

        return summary

# Example usage
async def main():
    engine = EnhancedSASTEngine()
    results = await engine.scan_directory(".")
    print(f"Found {results['summary']['total_findings']} issues")

if __name__ == "__main__":
    asyncio.run(main())