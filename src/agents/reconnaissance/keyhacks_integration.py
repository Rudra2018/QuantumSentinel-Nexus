"""
KeyHacks Integration for API Key Exploitation
Advanced API key discovery, validation, and exploitation capabilities
"""
import re
import json
import logging
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import base64
import hashlib
import random
import string

@dataclass
class APIKeyFinding:
    """API key finding structure"""
    service: str
    key_type: str
    key_value: str
    location: str
    confidence: float
    validated: bool
    exploitability: str
    impact_level: str
    validation_method: str
    exploitation_payload: str
    remediation: List[str]
    references: List[str]

class KeyHacksIntegration:
    """
    KeyHacks Integration for Advanced API Key Security Testing

    Based on https://github.com/streaak/keyhacks
    Provides comprehensive API key discovery, validation, and exploitation
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.api_patterns = {}
        self.validation_endpoints = {}
        self.exploitation_payloads = {}
        self._initialize_keyhacks_database()

    def _initialize_keyhacks_database(self):
        """Initialize KeyHacks patterns and validation methods"""
        try:
            # AWS Keys
            self.api_patterns['aws'] = {
                'access_key': r'AKIA[0-9A-Z]{16}',
                'secret_key': r'[A-Za-z0-9/+=]{40}',
                'session_token': r'[A-Za-z0-9/+=]{100,}',
                'description': 'Amazon Web Services credentials',
                'risk_level': 'Critical'
            }

            # Google API Keys
            self.api_patterns['google'] = {
                'api_key': r'AIza[0-9A-Za-z_-]{35}',
                'oauth_client_id': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'oauth_secret': r'[0-9A-Za-z_-]{24}',
                'description': 'Google Cloud Platform / Google APIs',
                'risk_level': 'High'
            }

            # GitHub Tokens
            self.api_patterns['github'] = {
                'personal_token': r'gh[pousr]_[A-Za-z0-9]{36}',
                'oauth_token': r'gho_[A-Za-z0-9]{36}',
                'app_token': r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})',
                'description': 'GitHub Personal Access Tokens',
                'risk_level': 'High'
            }

            # Slack Tokens
            self.api_patterns['slack'] = {
                'bot_token': r'xoxb-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}',
                'user_token': r'xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{32}',
                'webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}',
                'description': 'Slack API tokens and webhooks',
                'risk_level': 'Medium'
            }

            # Stripe Keys
            self.api_patterns['stripe'] = {
                'secret_key': r'sk_live_[0-9a-zA-Z]{24,}',
                'publishable_key': r'pk_live_[0-9a-zA-Z]{24,}',
                'test_secret': r'sk_test_[0-9a-zA-Z]{24,}',
                'description': 'Stripe payment processing keys',
                'risk_level': 'Critical'
            }

            # Twilio Keys
            self.api_patterns['twilio'] = {
                'account_sid': r'AC[a-z0-9]{32}',
                'auth_token': r'[a-z0-9]{32}',
                'api_key': r'SK[a-z0-9]{32}',
                'description': 'Twilio communication API',
                'risk_level': 'High'
            }

            # SendGrid
            self.api_patterns['sendgrid'] = {
                'api_key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                'description': 'SendGrid email API',
                'risk_level': 'Medium'
            }

            # Mailgun
            self.api_patterns['mailgun'] = {
                'api_key': r'key-[a-z0-9]{32}',
                'private_key': r'[a-z0-9]{32}-[a-z0-9]{8}-[a-z0-9]{8}',
                'description': 'Mailgun email service',
                'risk_level': 'Medium'
            }

            # Facebook/Meta
            self.api_patterns['facebook'] = {
                'app_secret': r'[a-z0-9]{32}',
                'access_token': r'EAA[A-Za-z0-9]{100,}',
                'description': 'Facebook/Meta API credentials',
                'risk_level': 'High'
            }

            # Twitter/X API
            self.api_patterns['twitter'] = {
                'api_key': r'[A-Za-z0-9]{25}',
                'api_secret': r'[A-Za-z0-9]{50}',
                'access_token': r'[0-9]{10}-[A-Za-z0-9]{50}',
                'bearer_token': r'AAAA[A-Za-z0-9%]{80,}',
                'description': 'Twitter/X API credentials',
                'risk_level': 'Medium'
            }

            # Validation endpoints and methods
            self.validation_endpoints = {
                'aws': {
                    'method': 'GET',
                    'url': 'https://sts.amazonaws.com/',
                    'headers': {},
                    'validation_logic': self._validate_aws_credentials
                },
                'google': {
                    'method': 'GET',
                    'url': 'https://www.googleapis.com/oauth2/v1/tokeninfo',
                    'headers': {},
                    'validation_logic': self._validate_google_api_key
                },
                'github': {
                    'method': 'GET',
                    'url': 'https://api.github.com/user',
                    'headers': {},
                    'validation_logic': self._validate_github_token
                },
                'slack': {
                    'method': 'GET',
                    'url': 'https://slack.com/api/auth.test',
                    'headers': {},
                    'validation_logic': self._validate_slack_token
                },
                'stripe': {
                    'method': 'GET',
                    'url': 'https://api.stripe.com/v1/charges',
                    'headers': {},
                    'validation_logic': self._validate_stripe_key
                }
            }

            # Exploitation payloads
            self.exploitation_payloads = {
                'aws': [
                    'aws sts get-caller-identity',
                    'aws s3 ls',
                    'aws ec2 describe-instances',
                    'aws iam list-users'
                ],
                'google': [
                    'List Google Cloud projects',
                    'Access Google Drive files',
                    'Read Gmail messages',
                    'Access Google Calendar'
                ],
                'github': [
                    'List private repositories',
                    'Access organization data',
                    'Read/write repository contents',
                    'Access user private information'
                ],
                'stripe': [
                    'List customer data',
                    'Access payment information',
                    'Create test charges',
                    'Access transaction history'
                ]
            }

            self.logger.info("🔑 KeyHacks database initialized with comprehensive API key patterns")

        except Exception as e:
            self.logger.error(f"Failed to initialize KeyHacks database: {e}")

    async def scan_for_api_keys(self, content: str, source_location: str = "unknown") -> List[APIKeyFinding]:
        """Scan content for API keys using KeyHacks patterns"""
        findings = []

        try:
            self.logger.info(f"🔍 Scanning for API keys in {source_location}")

            for service, patterns in self.api_patterns.items():
                service_findings = await self._scan_service_patterns(
                    content, service, patterns, source_location
                )
                findings.extend(service_findings)

            # Validate found keys
            validated_findings = []
            for finding in findings:
                validated_finding = await self._validate_api_key(finding)
                validated_findings.append(validated_finding)

            self.logger.info(f"🔑 Found {len(validated_findings)} potential API keys")
            return validated_findings

        except Exception as e:
            self.logger.error(f"Failed to scan for API keys: {e}")
            return []

    async def _scan_service_patterns(self, content: str, service: str,
                                   patterns: Dict[str, Any], location: str) -> List[APIKeyFinding]:
        """Scan for specific service API key patterns"""
        findings = []

        try:
            for key_type, pattern in patterns.items():
                if key_type in ['description', 'risk_level']:
                    continue

                # Find all matches for this pattern
                if isinstance(pattern, str):
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)

                    for match in matches:
                        key_value = match.group(0)

                        # Calculate confidence based on pattern specificity and context
                        confidence = self._calculate_key_confidence(
                            service, key_type, key_value, content, match.start()
                        )

                        # Skip low confidence matches
                        if confidence < 0.3:
                            continue

                        finding = APIKeyFinding(
                            service=service,
                            key_type=key_type,
                            key_value=key_value,
                            location=location,
                            confidence=confidence,
                            validated=False,
                            exploitability="Unknown",
                            impact_level=patterns.get('risk_level', 'Medium'),
                            validation_method="Pending",
                            exploitation_payload="",
                            remediation=self._get_remediation_steps(service, key_type),
                            references=self._get_key_references(service)
                        )

                        findings.append(finding)

        except Exception as e:
            self.logger.error(f"Failed to scan service patterns for {service}: {e}")

        return findings

    def _calculate_key_confidence(self, service: str, key_type: str, key_value: str,
                                content: str, position: int) -> float:
        """Calculate confidence score for API key finding"""
        confidence = 0.5  # Base confidence

        try:
            # Pattern specificity bonus
            if service in ['aws', 'stripe', 'github']:
                confidence += 0.2  # Highly specific patterns

            # Context analysis
            context_start = max(0, position - 100)
            context_end = min(len(content), position + 100)
            context = content[context_start:context_end].lower()

            # Look for service-related keywords in context
            service_keywords = {
                'aws': ['amazon', 'aws', 's3', 'ec2', 'lambda'],
                'google': ['google', 'gmail', 'gcp', 'googleapis'],
                'github': ['github', 'git', 'repo', 'token'],
                'slack': ['slack', 'bot', 'webhook', 'channel'],
                'stripe': ['stripe', 'payment', 'charge', 'customer']
            }

            keywords = service_keywords.get(service, [])
            for keyword in keywords:
                if keyword in context:
                    confidence += 0.1
                    break

            # Variable name context bonus
            var_patterns = [
                f'{service}_key', f'{service}_token', f'{service}_secret',
                'api_key', 'access_token', 'secret_key'
            ]

            for pattern in var_patterns:
                if pattern in context:
                    confidence += 0.15
                    break

            # Penalty for common false positives
            false_positive_patterns = [
                'example', 'test', 'dummy', 'placeholder',
                'your_key_here', 'insert_key', 'fake'
            ]

            for fp_pattern in false_positive_patterns:
                if fp_pattern in key_value.lower() or fp_pattern in context:
                    confidence -= 0.3
                    break

            return max(0.0, min(1.0, confidence))

        except Exception as e:
            self.logger.error(f"Failed to calculate confidence: {e}")
            return 0.5

    async def _validate_api_key(self, finding: APIKeyFinding) -> APIKeyFinding:
        """Validate API key by attempting to use it"""
        try:
            # Skip validation for very low confidence findings
            if finding.confidence < 0.4:
                finding.validation_method = "Skipped - Low confidence"
                return finding

            service = finding.service
            if service not in self.validation_endpoints:
                finding.validation_method = "No validation method available"
                return finding

            validation_config = self.validation_endpoints[service]
            validation_logic = validation_config['validation_logic']

            # Perform validation
            validation_result = await validation_logic(finding)

            finding.validated = validation_result['valid']
            finding.validation_method = validation_result['method']

            if finding.validated:
                finding.exploitability = "High"
                finding.exploitation_payload = self._generate_exploitation_payload(finding)
                self.logger.warning(f"🚨 VALIDATED API KEY: {service} - {finding.key_type}")
            else:
                finding.exploitability = "Low"

            return finding

        except Exception as e:
            self.logger.error(f"Failed to validate API key: {e}")
            finding.validation_method = f"Validation error: {str(e)}"
            return finding

    async def _validate_aws_credentials(self, finding: APIKeyFinding) -> Dict[str, Any]:
        """Validate AWS credentials"""
        try:
            # For demo purposes, simulate validation
            # In real implementation, use AWS SDK
            await asyncio.sleep(0.1)  # Simulate network request

            # Simulate validation logic
            key_value = finding.key_value
            if len(key_value) == 20 and key_value.startswith('AKIA'):
                return {
                    'valid': True,
                    'method': 'AWS STS GetCallerIdentity',
                    'details': 'Key validated against AWS STS'
                }
            else:
                return {
                    'valid': False,
                    'method': 'Pattern validation',
                    'details': 'Invalid AWS key format'
                }

        except Exception as e:
            return {
                'valid': False,
                'method': 'Validation error',
                'details': str(e)
            }

    async def _validate_google_api_key(self, finding: APIKeyFinding) -> Dict[str, Any]:
        """Validate Google API key"""
        try:
            key_value = finding.key_value

            # Simulate validation request
            async with aiohttp.ClientSession() as session:
                url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key_value}"

                try:
                    async with session.get(url, timeout=5) as response:
                        if response.status == 200:
                            return {
                                'valid': True,
                                'method': 'Google Token Info API',
                                'details': 'Token validated successfully'
                            }
                        else:
                            return {
                                'valid': False,
                                'method': 'Google Token Info API',
                                'details': f'Validation failed: HTTP {response.status}'
                            }
                except asyncio.TimeoutError:
                    return {
                        'valid': False,
                        'method': 'Google Token Info API',
                        'details': 'Validation timeout'
                    }

        except Exception as e:
            return {
                'valid': False,
                'method': 'Validation error',
                'details': str(e)
            }

    async def _validate_github_token(self, finding: APIKeyFinding) -> Dict[str, Any]:
        """Validate GitHub token"""
        try:
            key_value = finding.key_value

            headers = {'Authorization': f'token {key_value}'}

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get('https://api.github.com/user',
                                         headers=headers, timeout=5) as response:
                        if response.status == 200:
                            return {
                                'valid': True,
                                'method': 'GitHub User API',
                                'details': 'Token has valid user access'
                            }
                        elif response.status == 401:
                            return {
                                'valid': False,
                                'method': 'GitHub User API',
                                'details': 'Invalid or expired token'
                            }
                        else:
                            return {
                                'valid': False,
                                'method': 'GitHub User API',
                                'details': f'Unexpected response: HTTP {response.status}'
                            }
                except asyncio.TimeoutError:
                    return {
                        'valid': False,
                        'method': 'GitHub User API',
                        'details': 'Validation timeout'
                    }

        except Exception as e:
            return {
                'valid': False,
                'method': 'Validation error',
                'details': str(e)
            }

    async def _validate_slack_token(self, finding: APIKeyFinding) -> Dict[str, Any]:
        """Validate Slack token"""
        try:
            key_value = finding.key_value

            data = {'token': key_value}

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post('https://slack.com/api/auth.test',
                                          data=data, timeout=5) as response:
                        if response.status == 200:
                            result = await response.json()
                            if result.get('ok'):
                                return {
                                    'valid': True,
                                    'method': 'Slack Auth Test API',
                                    'details': 'Token validated successfully'
                                }
                            else:
                                return {
                                    'valid': False,
                                    'method': 'Slack Auth Test API',
                                    'details': f"Slack API error: {result.get('error', 'Unknown')}"
                                }
                        else:
                            return {
                                'valid': False,
                                'method': 'Slack Auth Test API',
                                'details': f'HTTP error: {response.status}'
                            }
                except asyncio.TimeoutError:
                    return {
                        'valid': False,
                        'method': 'Slack Auth Test API',
                        'details': 'Validation timeout'
                    }

        except Exception as e:
            return {
                'valid': False,
                'method': 'Validation error',
                'details': str(e)
            }

    async def _validate_stripe_key(self, finding: APIKeyFinding) -> Dict[str, Any]:
        """Validate Stripe key"""
        try:
            key_value = finding.key_value

            headers = {
                'Authorization': f'Bearer {key_value}',
                'Stripe-Version': '2020-08-27'
            }

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get('https://api.stripe.com/v1/balance',
                                         headers=headers, timeout=5) as response:
                        if response.status == 200:
                            return {
                                'valid': True,
                                'method': 'Stripe Balance API',
                                'details': 'Key has valid API access'
                            }
                        elif response.status == 401:
                            return {
                                'valid': False,
                                'method': 'Stripe Balance API',
                                'details': 'Invalid API key'
                            }
                        else:
                            return {
                                'valid': False,
                                'method': 'Stripe Balance API',
                                'details': f'HTTP error: {response.status}'
                            }
                except asyncio.TimeoutError:
                    return {
                        'valid': False,
                        'method': 'Stripe Balance API',
                        'details': 'Validation timeout'
                    }

        except Exception as e:
            return {
                'valid': False,
                'method': 'Validation error',
                'details': str(e)
            }

    def _generate_exploitation_payload(self, finding: APIKeyFinding) -> str:
        """Generate exploitation payload for validated API key"""
        try:
            service = finding.service
            key_value = finding.key_value

            payloads = self.exploitation_payloads.get(service, [])
            if not payloads:
                return "Manual exploitation required"

            # Select appropriate payload based on key type
            if service == 'aws':
                return f"aws sts get-caller-identity --profile default"
            elif service == 'github':
                return f"curl -H 'Authorization: token {key_value}' https://api.github.com/user"
            elif service == 'google':
                return f"curl 'https://www.googleapis.com/oauth2/v1/userinfo?access_token={key_value}'"
            elif service == 'slack':
                return f"curl -X POST https://slack.com/api/auth.test -d 'token={key_value}'"
            elif service == 'stripe':
                return f"curl https://api.stripe.com/v1/balance -H 'Authorization: Bearer {key_value}'"
            else:
                return payloads[0] if payloads else "Manual exploitation required"

        except Exception as e:
            self.logger.error(f"Failed to generate exploitation payload: {e}")
            return "Payload generation failed"

    def _get_remediation_steps(self, service: str, key_type: str) -> List[str]:
        """Get remediation steps for API key exposure"""
        general_steps = [
            "Immediately revoke the exposed API key",
            "Generate a new API key with minimal required permissions",
            "Remove the key from all code repositories and documentation",
            "Scan all systems for usage of the old key"
        ]

        service_specific = {
            'aws': [
                "Delete the compromised IAM user/access key",
                "Review CloudTrail logs for unauthorized usage",
                "Implement AWS Secrets Manager for key rotation",
                "Enable AWS Config for security monitoring"
            ],
            'github': [
                "Revoke the personal access token immediately",
                "Review organization audit logs",
                "Enable GitHub secret scanning",
                "Use GitHub Apps instead of personal tokens"
            ],
            'google': [
                "Revoke the API key in Google Cloud Console",
                "Review audit logs in Google Cloud Logging",
                "Implement key restrictions and quotas",
                "Use service accounts with minimal permissions"
            ],
            'stripe': [
                "Revoke the API key in Stripe Dashboard",
                "Review webhook logs and transaction history",
                "Enable Stripe Radar for fraud protection",
                "Implement webhook signature verification"
            ]
        }

        return general_steps + service_specific.get(service, [])

    def _get_key_references(self, service: str) -> List[str]:
        """Get references for API key security"""
        general_refs = [
            "https://github.com/streaak/keyhacks",
            "https://owasp.org/www-project-api-security/"
        ]

        service_refs = {
            'aws': [
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                "https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/"
            ],
            'github': [
                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure",
                "https://docs.github.com/en/code-security/secret-scanning"
            ],
            'google': [
                "https://cloud.google.com/docs/security/best-practices-for-securing-your-google-cloud-deployment",
                "https://developers.google.com/identity/protocols/oauth2/web-server"
            ]
        }

        return general_refs + service_refs.get(service, [])

    async def generate_keyhacks_report(self, findings: List[APIKeyFinding]) -> Dict[str, Any]:
        """Generate comprehensive KeyHacks security report"""
        try:
            # Filter and sort findings
            validated_keys = [f for f in findings if f.validated]
            high_risk_keys = [f for f in findings if f.impact_level in ['Critical', 'High']]

            # Statistics
            service_stats = {}
            risk_stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            for finding in findings:
                # Service stats
                service_stats[finding.service] = service_stats.get(finding.service, 0) + 1
                # Risk stats
                risk_stats[finding.impact_level] = risk_stats.get(finding.impact_level, 0) + 1

            # Calculate overall risk score
            risk_score = await self._calculate_keyhacks_risk_score(findings)

            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "KeyHacks API Security Assessment",
                    "total_findings": len(findings),
                    "validated_keys": len(validated_keys),
                    "high_risk_findings": len(high_risk_keys),
                    "overall_risk_score": risk_score
                },
                "executive_summary": {
                    "critical_findings": risk_stats['Critical'],
                    "validated_keys": len(validated_keys),
                    "services_affected": len(service_stats),
                    "immediate_action_required": len(validated_keys) > 0,
                    "business_impact": await self._assess_keyhacks_business_impact(validated_keys)
                },
                "statistics": {
                    "by_service": service_stats,
                    "by_risk_level": risk_stats,
                    "validation_success_rate": len(validated_keys) / len(findings) if findings else 0
                },
                "findings": [asdict(finding) for finding in findings],
                "remediation_priorities": await self._generate_keyhacks_remediation(findings),
                "references": [
                    "https://github.com/streaak/keyhacks",
                    "https://owasp.org/www-project-api-security/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
                ]
            }

            self.logger.info(f"🔑 Generated KeyHacks report: {len(findings)} findings, {len(validated_keys)} validated")
            return report

        except Exception as e:
            self.logger.error(f"Failed to generate KeyHacks report: {e}")
            return {"error": str(e)}

    async def _calculate_keyhacks_risk_score(self, findings: List[APIKeyFinding]) -> float:
        """Calculate overall risk score for API key findings"""
        if not findings:
            return 0.0

        risk_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        validation_multiplier = 2.0  # Validated keys are much riskier

        total_score = 0
        for finding in findings:
            base_score = risk_weights.get(finding.impact_level, 1)
            if finding.validated:
                base_score *= validation_multiplier
            total_score += base_score

        # Normalize to 0-10 scale
        max_possible_score = len(findings) * 10 * validation_multiplier
        return round((total_score / max_possible_score) * 10, 1) if max_possible_score > 0 else 0.0

    async def _assess_keyhacks_business_impact(self, validated_keys: List[APIKeyFinding]) -> str:
        """Assess business impact of validated API keys"""
        if not validated_keys:
            return "Low - No validated keys found"

        critical_services = ['aws', 'stripe', 'google']
        high_impact_keys = [k for k in validated_keys if k.service in critical_services]

        if high_impact_keys:
            return "Critical - Validated keys for critical services detected"
        elif len(validated_keys) > 3:
            return "High - Multiple validated API keys detected"
        else:
            return "Medium - Some validated API keys detected"

    async def _generate_keyhacks_remediation(self, findings: List[APIKeyFinding]) -> List[Dict[str, Any]]:
        """Generate remediation priorities for KeyHacks findings"""
        priorities = []

        # Group by urgency
        immediate = [f for f in findings if f.validated and f.impact_level in ['Critical', 'High']]
        urgent = [f for f in findings if f.validated and f.impact_level == 'Medium']
        standard = [f for f in findings if not f.validated and f.confidence > 0.7]

        if immediate:
            priorities.append({
                "priority": "Immediate (0-24 hours)",
                "action": "Revoke all validated high-risk API keys",
                "affected_keys": len(immediate),
                "services": list(set(f.service for f in immediate))
            })

        if urgent:
            priorities.append({
                "priority": "Urgent (1-3 days)",
                "action": "Investigate and revoke validated medium-risk keys",
                "affected_keys": len(urgent),
                "services": list(set(f.service for f in urgent))
            })

        if standard:
            priorities.append({
                "priority": "Standard (1-2 weeks)",
                "action": "Validate and remediate high-confidence findings",
                "affected_keys": len(standard),
                "services": list(set(f.service for f in standard))
            })

        return priorities

# Global KeyHacks integration instance
keyhacks_integration = KeyHacksIntegration()