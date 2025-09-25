#!/usr/bin/env python3
"""
🎯 BUG BOUNTY MODULE
==================
Advanced bug bounty vulnerability assessment module integrating industry-standard
tools for comprehensive security testing and high-value vulnerability discovery.
"""

import os
import json
import asyncio
import subprocess
import tempfile
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import logging
import aiofiles
from datetime import datetime
import urllib.parse
import base64
import random
import time

class BugBountyModule:
    def __init__(self, workspace: Path, config: Dict, logger: logging.Logger):
        """Initialize bug bounty module"""
        self.workspace = workspace
        self.config = config
        self.logger = logger
        self.bugbounty_config = config.get('modules', {}).get('bugbounty', {})

        # Results storage
        self.results = {
            'sql_injections': [],
            'xss_vulnerabilities': [],
            'ssrf_findings': [],
            'open_redirects': [],
            'directory_traversals': [],
            'api_key_exposures': [],
            'cors_misconfigurations': [],
            'subdomain_takeovers': [],
            'directory_listings': [],
            'parameter_pollution': [],
            'sensitive_files': [],
            'high_value_findings': []
        }

        # Rate limiting
        self.request_delay = 0.5  # 500ms between requests
        self.last_request_time = 0

        self.logger.info("Bug bounty module initialized")

    async def run_sqlmap(self, targets: List[str]) -> Dict:
        """Run SQLMap for SQL injection detection"""
        self.logger.info(f"Running SQLMap on {len(targets)} targets")

        sql_findings = []
        sqlmap_config = self.bugbounty_config.get('sqlmap', {})

        for target in targets[:10]:  # Limit to first 10 targets for ethical testing
            await self.rate_limit()

            # Create temporary target file
            temp_file = self.workspace / f'bugbounty/sqlmap_target_{hash(target)}.txt'
            async with aiofiles.open(temp_file, 'w') as f:
                await f.write(target)

            output_dir = self.workspace / f'bugbounty/sqlmap_{hash(target)}'
            output_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                'sqlmap',
                '-u', target,
                '--batch',  # Non-interactive mode
                '--crawl=2',  # Crawl depth
                '--level', str(sqlmap_config.get('level', 3)),
                '--risk', str(sqlmap_config.get('risk_level', 2)),
                '--timeout', str(sqlmap_config.get('timeout', 30)),
                '--threads', str(sqlmap_config.get('threads', 5)),
                '--output-dir', str(output_dir),
                '--format=JSON'
            ]

            try:
                result = await self.run_command(cmd, timeout=300)

                # Parse SQLMap results
                log_files = list(output_dir.glob('**/*.log'))
                for log_file in log_files:
                    async with aiofiles.open(log_file, 'r') as f:
                        content = await f.read()
                        if 'sqlmap identified the following injection point(s)' in content:
                            sql_findings.append({
                                'target': target,
                                'vulnerability': 'SQL Injection',
                                'severity': 'high',
                                'details': 'SQLMap detected potential SQL injection',
                                'evidence': str(log_file),
                                'tool': 'sqlmap'
                            })

            except Exception as e:
                self.logger.warning(f"SQLMap failed for {target}: {e}")
                continue

        self.results['sql_injections'].extend(sql_findings)

        return {
            'tool': 'sqlmap',
            'targets': targets,
            'findings': sql_findings,
            'count': len(sql_findings),
            'status': 'completed'
        }

    async def run_xsstrike(self, targets: List[str]) -> Dict:
        """Run XSStrike for XSS vulnerability detection"""
        self.logger.info(f"Running XSStrike on {len(targets)} targets")

        xss_findings = []

        for target in targets[:15]:  # Limit for ethical testing
            await self.rate_limit()

            output_file = self.workspace / f'bugbounty/xsstrike_{hash(target)}.json'

            cmd = [
                'xsstrike',
                '-u', target,
                '--crawl',
                '--timeout', '30',
                '--skip-dom',  # Skip DOM-based XSS for faster scanning
                '--json-output', str(output_file)
            ]

            try:
                result = await self.run_command(cmd, timeout=180)

                # Parse results
                if output_file.exists():
                    async with aiofiles.open(output_file, 'r') as f:
                        content = await f.read()
                        try:
                            data = json.loads(content)
                            if data.get('vulnerabilities'):
                                for vuln in data['vulnerabilities']:
                                    xss_findings.append({
                                        'target': target,
                                        'vulnerability': 'Cross-Site Scripting (XSS)',
                                        'severity': 'medium',
                                        'parameter': vuln.get('parameter', ''),
                                        'payload': vuln.get('payload', ''),
                                        'evidence': str(output_file),
                                        'tool': 'xsstrike'
                                    })
                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                self.logger.warning(f"XSStrike failed for {target}: {e}")
                continue

        self.results['xss_vulnerabilities'].extend(xss_findings)

        return {
            'tool': 'xsstrike',
            'targets': targets,
            'findings': xss_findings,
            'count': len(xss_findings),
            'status': 'completed'
        }

    async def run_dirsearch(self, targets: List[str]) -> Dict:
        """Run Dirsearch for directory enumeration"""
        self.logger.info(f"Running Dirsearch on {len(targets)} targets")

        directory_findings = []
        dirsearch_config = self.bugbounty_config.get('dirsearch', {})

        for target in targets[:10]:  # Ethical limitation
            await self.rate_limit()

            output_file = self.workspace / f'bugbounty/dirsearch_{hash(target)}.json'

            # Get wordlists
            wordlists = dirsearch_config.get('wordlists', ['common.txt'])
            extensions = ','.join(dirsearch_config.get('extensions', ['php', 'html', 'js']))

            cmd = [
                'dirsearch',
                '-u', target,
                '-e', extensions,
                '--format=json',
                '-o', str(output_file),
                '--threads', str(dirsearch_config.get('threads', 20)),
                '--timeout', '15',
                '--exclude-status', '404,403,400'
            ]

            # Add wordlist if available
            if wordlists:
                cmd.extend(['-w', wordlists[0]])  # Use first wordlist

            try:
                result = await self.run_command(cmd, timeout=300)

                # Parse results
                if output_file.exists():
                    async with aiofiles.open(output_file, 'r') as f:
                        content = await f.read()
                        try:
                            data = json.loads(content)
                            for result_item in data.get('results', []):
                                status = result_item.get('status')
                                url = result_item.get('url', '')

                                if status in [200, 301, 302, 500]:
                                    directory_findings.append({
                                        'target': target,
                                        'vulnerability': 'Directory/File Exposure',
                                        'severity': 'low' if status == 200 else 'info',
                                        'url': url,
                                        'status_code': status,
                                        'evidence': str(output_file),
                                        'tool': 'dirsearch'
                                    })
                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                self.logger.warning(f"Dirsearch failed for {target}: {e}")
                continue

        self.results['directory_listings'].extend(directory_findings)

        return {
            'tool': 'dirsearch',
            'targets': targets,
            'findings': directory_findings,
            'count': len(directory_findings),
            'status': 'completed'
        }

    async def run_keyhacks(self, api_keys: List[str]) -> Dict:
        """Run KeyHacks for API key validation"""
        self.logger.info(f"Running KeyHacks on {len(api_keys)} API keys")

        keyhacks_findings = []

        for api_key in api_keys:
            await self.rate_limit()

            # Detect key type based on pattern
            key_type = self.detect_api_key_type(api_key)
            if not key_type:
                continue

            output_file = self.workspace / f'bugbounty/keyhacks_{hash(api_key)}.json'

            cmd = [
                'keyhacks',
                '--key', api_key,
                '--service', key_type,
                '--output', str(output_file),
                '--timeout', '30'
            ]

            try:
                result = await self.run_command(cmd, timeout=60)

                # Parse results
                if output_file.exists():
                    async with aiofiles.open(output_file, 'r') as f:
                        content = await f.read()
                        try:
                            data = json.loads(content)
                            if data.get('valid') or data.get('active'):
                                keyhacks_findings.append({
                                    'vulnerability': 'Active API Key Exposure',
                                    'severity': 'critical',
                                    'key_type': key_type,
                                    'key_preview': api_key[:10] + '...',
                                    'validation_result': data,
                                    'evidence': str(output_file),
                                    'tool': 'keyhacks'
                                })
                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                self.logger.warning(f"KeyHacks failed for key {api_key[:10]}...: {e}")
                continue

        self.results['api_key_exposures'].extend(keyhacks_findings)

        return {
            'tool': 'keyhacks',
            'api_keys': len(api_keys),
            'findings': keyhacks_findings,
            'count': len(keyhacks_findings),
            'status': 'completed'
        }

    async def run_ffuf(self, targets: List[str]) -> Dict:
        """Run FFUF for parameter fuzzing and discovery"""
        self.logger.info(f"Running FFUF on {len(targets)} targets")

        ffuf_findings = []

        for target in targets[:8]:  # Ethical limitation
            await self.rate_limit()

            output_file = self.workspace / f'bugbounty/ffuf_{hash(target)}.json'

            # Parameter fuzzing
            cmd = [
                'ffuf',
                '-u', f'{target}?FUZZ=test',
                '-w', '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
                '-mc', '200,301,302,403',
                '-o', str(output_file),
                '-of', 'json',
                '-t', '50',  # Threads
                '-p', '0.1',  # Delay between requests
                '-timeout', '10'
            ]

            try:
                result = await self.run_command(cmd, timeout=300)

                # Parse results
                if output_file.exists():
                    async with aiofiles.open(output_file, 'r') as f:
                        content = await f.read()
                        try:
                            data = json.loads(content)
                            for result_item in data.get('results', []):
                                parameter = result_item.get('input', {}).get('FUZZ', '')
                                status = result_item.get('status', 0)

                                if status in [200, 301, 302] and parameter:
                                    ffuf_findings.append({
                                        'target': target,
                                        'vulnerability': 'Parameter Discovery',
                                        'severity': 'info',
                                        'parameter': parameter,
                                        'status_code': status,
                                        'evidence': str(output_file),
                                        'tool': 'ffuf'
                                    })
                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                self.logger.warning(f"FFUF failed for {target}: {e}")
                continue

        self.results['parameter_pollution'].extend(ffuf_findings)

        return {
            'tool': 'ffuf',
            'targets': targets,
            'findings': ffuf_findings,
            'count': len(ffuf_findings),
            'status': 'completed'
        }

    async def test_cors_misconfiguration(self, targets: List[str]) -> Dict:
        """Test for CORS misconfigurations"""
        self.logger.info(f"Testing CORS on {len(targets)} targets")

        cors_findings = []

        malicious_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            'https://subdomain.target.com'
        ]

        for target in targets:
            await self.rate_limit()

            for origin in malicious_origins:
                try:
                    # Simulate CORS preflight request
                    cmd = [
                        'curl',
                        '-s', '-I',
                        '-H', f'Origin: {origin}',
                        '-H', 'Access-Control-Request-Method: POST',
                        '-H', 'Access-Control-Request-Headers: Content-Type',
                        target
                    ]

                    result = await self.run_command(cmd, timeout=30)
                    headers = result.stdout.decode()

                    if 'Access-Control-Allow-Origin' in headers:
                        if origin in headers or '*' in headers:
                            cors_findings.append({
                                'target': target,
                                'vulnerability': 'CORS Misconfiguration',
                                'severity': 'medium',
                                'origin': origin,
                                'details': 'Server accepts potentially malicious origin',
                                'evidence': headers,
                                'tool': 'cors_test'
                            })

                except Exception as e:
                    self.logger.debug(f"CORS test failed for {target} with origin {origin}: {e}")
                    continue

        self.results['cors_misconfigurations'].extend(cors_findings)

        return {
            'tool': 'cors_test',
            'targets': targets,
            'findings': cors_findings,
            'count': len(cors_findings),
            'status': 'completed'
        }

    async def test_open_redirects(self, targets: List[str]) -> Dict:
        """Test for open redirect vulnerabilities"""
        self.logger.info(f"Testing open redirects on {len(targets)} targets")

        redirect_findings = []

        redirect_payloads = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            '/\\evil.com',
            'javascript:alert(1)'
        ]

        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'redirect_uri']

        for target in targets:
            for param in redirect_params:
                for payload in redirect_payloads:
                    await self.rate_limit()

                    test_url = f"{target}?{param}={urllib.parse.quote(payload)}"

                    try:
                        cmd = [
                            'curl',
                            '-s', '-I',
                            '--max-redirs', '0',
                            test_url
                        ]

                        result = await self.run_command(cmd, timeout=15)
                        headers = result.stdout.decode()

                        if result.returncode in [301, 302, 307, 308]:
                            if 'evil.com' in headers or 'javascript:' in headers:
                                redirect_findings.append({
                                    'target': target,
                                    'vulnerability': 'Open Redirect',
                                    'severity': 'medium',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': headers,
                                    'tool': 'open_redirect_test'
                                })

                    except Exception as e:
                        continue

        self.results['open_redirects'].extend(redirect_findings)

        return {
            'tool': 'open_redirect_test',
            'targets': targets,
            'findings': redirect_findings,
            'count': len(redirect_findings),
            'status': 'completed'
        }

    async def test_subdomain_takeover(self, subdomains: List[str]) -> Dict:
        """Test for subdomain takeover vulnerabilities"""
        self.logger.info(f"Testing subdomain takeover on {len(subdomains)} subdomains")

        takeover_findings = []

        # Common CNAME patterns indicating potential takeover
        vulnerable_patterns = [
            'github.io',
            'herokuapp.com',
            'wordpress.com',
            'tumblr.com',
            'shopify.com',
            'surge.sh',
            'bitbucket.io'
        ]

        for subdomain in subdomains:
            await self.rate_limit()

            try:
                # Check DNS records
                cmd = ['dig', '+short', 'CNAME', subdomain]
                result = await self.run_command(cmd, timeout=10)
                cname = result.stdout.decode().strip()

                for pattern in vulnerable_patterns:
                    if pattern in cname:
                        # Verify if service responds with takeover indicators
                        test_cmd = ['curl', '-s', '-H', 'User-Agent: QuantumSentinel', f'https://{subdomain}']
                        test_result = await self.run_command(test_cmd, timeout=15)
                        response = test_result.stdout.decode()

                        if any(indicator in response.lower() for indicator in
                              ['not found', 'no such app', 'domain not configured']):
                            takeover_findings.append({
                                'subdomain': subdomain,
                                'vulnerability': 'Subdomain Takeover',
                                'severity': 'high',
                                'cname': cname,
                                'service': pattern,
                                'evidence': response[:500],
                                'tool': 'subdomain_takeover_test'
                            })

            except Exception as e:
                continue

        self.results['subdomain_takeovers'].extend(takeover_findings)

        return {
            'tool': 'subdomain_takeover_test',
            'subdomains': subdomains,
            'findings': takeover_findings,
            'count': len(takeover_findings),
            'status': 'completed'
        }

    def detect_api_key_type(self, api_key: str) -> Optional[str]:
        """Detect API key type based on pattern"""
        patterns = {
            'github': r'gh[pousr]_[A-Za-z0-9]{36}',
            'slack': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
            'aws': r'AKIA[0-9A-Z]{16}',
            'google': r'AIza[0-9A-Za-z\\-_]{35}',
            'stripe': r'sk_live_[0-9a-zA-Z]{24}',
            'twitter': r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
            'facebook': r'EAA[0-9A-Za-z\\-_]{90,}'
        }

        import re
        for key_type, pattern in patterns.items():
            if re.search(pattern, api_key):
                return key_type

        return None

    async def consolidate_high_value_findings(self) -> Dict:
        """Consolidate high-value findings for bug bounty submission"""
        self.logger.info("Consolidating high-value findings")

        high_value = []

        # Prioritize findings by severity and bug bounty value
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

        all_findings = []
        for finding_type, findings in self.results.items():
            for finding in findings:
                finding['category'] = finding_type
                all_findings.append(finding)

        # Sort by severity and potential value
        sorted_findings = sorted(all_findings,
                               key=lambda x: severity_scores.get(x.get('severity', 'low'), 0),
                               reverse=True)

        # Select top findings
        high_value = sorted_findings[:20]  # Top 20 findings

        # Enhance with bug bounty context
        for finding in high_value:
            finding['bug_bounty_impact'] = self.assess_bug_bounty_impact(finding)
            finding['remediation_priority'] = self.get_remediation_priority(finding)

        self.results['high_value_findings'] = high_value

        # Save consolidated results
        output_file = self.workspace / 'bugbounty/high_value_findings.json'
        async with aiofiles.open(output_file, 'w') as f:
            await f.write(json.dumps(high_value, indent=2, default=str))

        return {
            'high_value_findings': high_value,
            'total_findings': len(all_findings),
            'critical_count': len([f for f in all_findings if f.get('severity') == 'critical']),
            'high_count': len([f for f in all_findings if f.get('severity') == 'high']),
            'medium_count': len([f for f in all_findings if f.get('severity') == 'medium'])
        }

    def assess_bug_bounty_impact(self, finding: Dict) -> str:
        """Assess bug bounty impact for a finding"""
        vuln_type = finding.get('vulnerability', '').lower()
        severity = finding.get('severity', 'low')

        if 'sql injection' in vuln_type and severity in ['critical', 'high']:
            return 'High - Data breach potential, likely $1000-$5000 range'
        elif 'subdomain takeover' in vuln_type:
            return 'High - Brand hijacking, $500-$2000 range'
        elif 'api key exposure' in vuln_type and severity == 'critical':
            return 'Critical - Service compromise, $2000-$10000 range'
        elif 'cors misconfiguration' in vuln_type:
            return 'Medium - Data theft via CORS, $200-$1000 range'
        elif 'xss' in vuln_type:
            return 'Medium - Account takeover potential, $100-$800 range'
        else:
            return 'Low-Medium - Information disclosure, $50-$300 range'

    def get_remediation_priority(self, finding: Dict) -> str:
        """Get remediation priority"""
        severity = finding.get('severity', 'low')

        if severity == 'critical':
            return 'Immediate (0-24 hours)'
        elif severity == 'high':
            return 'High (24-72 hours)'
        elif severity == 'medium':
            return 'Medium (1-2 weeks)'
        else:
            return 'Low (1 month)'

    async def rate_limit(self):
        """Implement rate limiting for ethical testing"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.request_delay:
            await asyncio.sleep(self.request_delay - time_since_last)

        self.last_request_time = time.time()

    async def run_command(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run command with async subprocess"""
        self.logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            return subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr
            )

        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds")
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise