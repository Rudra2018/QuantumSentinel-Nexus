#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Base Bug Bounty Platform Integration
Foundation class for all bug bounty platform agents

Supported Platforms:
- HackerOne
- Bugcrowd  
- Intigriti
- Google VRP
- Apple Security
- Microsoft MSRC
"""

import asyncio
import aiohttp
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import time
from urllib.parse import urljoin, urlparse
import re

# Import security manager
try:
    from core.security.security_manager import SecurityManager, InputValidator
except ImportError:
    SecurityManager = None
    InputValidator = None

@dataclass
class Program:
    """Bug bounty program definition"""
    platform: str
    program_id: str
    name: str
    company: str
    scope: List[Dict[str, Any]]
    out_of_scope: List[Dict[str, Any]]
    rewards: Dict[str, Any]
    submission_guidelines: Dict[str, str]
    last_updated: datetime
    status: str  # active, paused, closed
    metrics: Dict[str, Any]
    
@dataclass
class ScopeRule:
    """Scope rule for bug bounty program"""
    rule_type: str  # domain, subdomain, ip_range, mobile_app, api
    target: str
    description: str
    severity_cap: Optional[str] = None
    special_instructions: Optional[str] = None
    testing_allowed: bool = True

@dataclass
class Vulnerability:
    """Vulnerability finding for bug bounty submission"""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    vulnerability_type: str
    affected_url: str
    proof_of_concept: str
    impact: str
    remediation: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: List[str] = None
    discovered_at: datetime = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()

@dataclass
class SubmissionResult:
    """Result of vulnerability submission"""
    submission_id: str
    status: str  # submitted, accepted, rejected, duplicate, informative
    platform_response: Dict[str, Any]
    submission_date: datetime
    estimated_response_time: Optional[timedelta] = None
    error_message: Optional[str] = None

class BasePlatformAgent(ABC):
    """Base class for bug bounty platform integration agents"""
    
    def __init__(self, platform_name: str, api_config: Dict[str, Any]):
        self.platform_name = platform_name
        self.api_config = api_config
        self.logger = logging.getLogger(f"QuantumSentinel.BugBounty.{platform_name}")
        
        # Security and validation
        self.security_manager = SecurityManager() if SecurityManager else None
        self.validator = InputValidator() if InputValidator else None
        
        # Rate limiting specific to platform
        self.rate_limits = {
            'requests_per_minute': api_config.get('rate_limit_rpm', 60),
            'requests_per_hour': api_config.get('rate_limit_rph', 1000),
            'concurrent_requests': api_config.get('max_concurrent', 5)
        }
        
        # Session management
        self.session = None
        self.authenticated = False
        
        # Cache for program data
        self.program_cache = {}
        self.cache_ttl = timedelta(hours=1)
        
        # Metrics tracking
        self.metrics = {
            'requests_made': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'submissions_made': 0,
            'programs_fetched': 0,
            'last_activity': None
        }
    
    async def initialize(self) -> bool:
        """Initialize platform agent"""
        try:
            # Create HTTP session
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self._get_default_headers()
            )
            
            # Authenticate with platform
            auth_success = await self._authenticate()
            if not auth_success:
                self.logger.error(f"Authentication failed for {self.platform_name}")
                return False
            
            self.authenticated = True
            self.logger.info(f"✅ {self.platform_name} agent initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.platform_name} agent: {e}")
            return False
    
    @abstractmethod
    async def _authenticate(self) -> bool:
        """Platform-specific authentication"""
        pass
    
    @abstractmethod
    def _get_default_headers(self) -> Dict[str, str]:
        """Get platform-specific default headers"""
        pass
    
    @abstractmethod
    async def get_programs(self, filters: Optional[Dict[str, Any]] = None) -> List[Program]:
        """Fetch available bug bounty programs"""
        pass
    
    @abstractmethod
    async def get_program_details(self, program_id: str) -> Optional[Program]:
        """Get detailed information about a specific program"""
        pass
    
    @abstractmethod
    async def validate_scope(self, target: str, program_id: str) -> Tuple[bool, str]:
        """Validate if target is within program scope"""
        pass
    
    @abstractmethod
    async def submit_finding(self, vulnerability: Vulnerability, program_id: str) -> SubmissionResult:
        """Submit vulnerability finding to platform"""
        pass
    
    @abstractmethod
    async def check_submission_status(self, submission_id: str) -> Dict[str, Any]:
        """Check status of submitted vulnerability"""
        pass
    
    async def _make_request(self, method: str, url: str, **kwargs) -> Tuple[bool, Any]:
        """Make secure HTTP request with rate limiting and error handling"""
        if not self.session:
            return False, "Session not initialized"
        
        try:
            # Rate limiting check
            await self._check_rate_limits()
            
            # Update metrics
            self.metrics['requests_made'] += 1
            self.metrics['last_activity'] = datetime.utcnow()
            
            # Make request
            async with self.session.request(method, url, **kwargs) as response:
                response_data = None
                
                # Handle different content types
                content_type = response.headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    response_data = await response.json()
                else:
                    response_data = await response.text()
                
                if response.status >= 200 and response.status < 300:
                    self.metrics['successful_requests'] += 1
                    return True, response_data
                else:
                    self.metrics['failed_requests'] += 1
                    error_msg = f"HTTP {response.status}: {response_data}"
                    self.logger.warning(f"Request failed: {error_msg}")
                    return False, error_msg
                    
        except asyncio.TimeoutError:
            self.metrics['failed_requests'] += 1
            self.logger.error(f"Request timeout for {method} {url}")
            return False, "Request timeout"
        except Exception as e:
            self.metrics['failed_requests'] += 1
            self.logger.error(f"Request error for {method} {url}: {e}")
            return False, str(e)
    
    async def _check_rate_limits(self):
        """Simple rate limiting implementation"""
        # This is a basic implementation
        # In production, use Redis or similar for distributed rate limiting
        await asyncio.sleep(60 / self.rate_limits['requests_per_minute'])
    
    def _validate_target_format(self, target: str) -> bool:
        """Validate target format and security"""
        if self.validator:
            return self.validator.validate_target(target)
        
        # Fallback validation if security manager not available
        if not target or len(target) > 253:
            return False
        
        # Basic domain/IP validation
        domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$')
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        return bool(domain_pattern.match(target) or ip_pattern.match(target))
    
    def _parse_scope_rules(self, scope_data: List[Dict[str, Any]]) -> List[ScopeRule]:
        """Parse scope rules from platform data"""
        rules = []
        
        for item in scope_data:
            try:
                rule = ScopeRule(
                    rule_type=item.get('type', 'domain'),
                    target=item.get('target', ''),
                    description=item.get('description', ''),
                    severity_cap=item.get('severity_cap'),
                    special_instructions=item.get('instructions'),
                    testing_allowed=item.get('testing_allowed', True)
                )
                rules.append(rule)
            except Exception as e:
                self.logger.warning(f"Failed to parse scope rule: {item} - {e}")
        
        return rules
    
    def _match_scope_rule(self, target: str, rule: ScopeRule) -> bool:
        """Check if target matches scope rule"""
        try:
            if rule.rule_type == 'domain':
                return target == rule.target or target.endswith(f'.{rule.target}')
            elif rule.rule_type == 'subdomain':
                return target.endswith(f'.{rule.target}') or target == rule.target
            elif rule.rule_type == 'wildcard':
                pattern = rule.target.replace('*', '.*')
                return bool(re.match(pattern, target))
            else:
                return target == rule.target
        except Exception as e:
            self.logger.error(f"Error matching scope rule: {e}")
            return False
    
    def _calculate_submission_priority(self, vulnerability: Vulnerability) -> int:
        """Calculate submission priority based on severity and type"""
        severity_weights = {
            'critical': 100,
            'high': 80,
            'medium': 60,
            'low': 40,
            'info': 20
        }
        
        type_weights = {
            'sql_injection': 20,
            'rce': 25,
            'authentication_bypass': 20,
            'privilege_escalation': 18,
            'xss': 15,
            'csrf': 10,
            'information_disclosure': 8,
            'other': 5
        }
        
        severity_score = severity_weights.get(vulnerability.severity.lower(), 20)
        type_score = type_weights.get(vulnerability.vulnerability_type.lower(), 5)
        
        # CVSS bonus
        cvss_bonus = int(vulnerability.cvss_score * 2) if vulnerability.cvss_score else 0
        
        return severity_score + type_score + cvss_bonus
    
    def _format_submission_data(self, vulnerability: Vulnerability, program_id: str) -> Dict[str, Any]:
        """Format vulnerability data for platform submission"""
        return {
            'program_id': program_id,
            'title': vulnerability.title,
            'description': vulnerability.description,
            'severity': vulnerability.severity,
            'vulnerability_type': vulnerability.vulnerability_type,
            'affected_url': vulnerability.affected_url,
            'proof_of_concept': vulnerability.proof_of_concept,
            'impact': vulnerability.impact,
            'remediation': vulnerability.remediation,
            'cvss_score': vulnerability.cvss_score,
            'cvss_vector': vulnerability.cvss_vector,
            'references': vulnerability.references,
            'discovered_at': vulnerability.discovered_at.isoformat(),
            'priority': self._calculate_submission_priority(vulnerability)
        }
    
    async def get_platform_stats(self) -> Dict[str, Any]:
        """Get platform-specific statistics"""
        return {
            'platform': self.platform_name,
            'authenticated': self.authenticated,
            'metrics': self.metrics.copy(),
            'cached_programs': len(self.program_cache),
            'rate_limits': self.rate_limits.copy(),
            'last_activity': self.metrics.get('last_activity')
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform platform health check"""
        health_status = {
            'platform': self.platform_name,
            'status': 'unknown',
            'authenticated': self.authenticated,
            'session_active': self.session is not None,
            'last_activity': self.metrics.get('last_activity'),
            'error': None
        }
        
        try:
            # Attempt a simple API call to test connectivity
            success, response = await self._health_check_request()
            if success:
                health_status['status'] = 'healthy'
            else:
                health_status['status'] = 'degraded'
                health_status['error'] = str(response)
                
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status
    
    @abstractmethod
    async def _health_check_request(self) -> Tuple[bool, Any]:
        """Platform-specific health check request"""
        pass
    
    async def cleanup(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None
        
        self.authenticated = False
        self.program_cache.clear()
        
        self.logger.info(f"✅ {self.platform_name} agent cleaned up")
    
    def __del__(self):
        """Ensure cleanup on deletion"""
        if self.session and not self.session.closed:
            try:
                asyncio.create_task(self.session.close())
            except:
                pass

# Utility functions for bug bounty platform integration
def calculate_cvss_score(vulnerability_type: str, impact: str, exploitability: str) -> Tuple[float, str]:
    """Calculate CVSS score and vector"""
    # Simplified CVSS calculation
    base_scores = {
        'sql_injection': 8.8,
        'rce': 9.0,
        'authentication_bypass': 8.1,
        'privilege_escalation': 7.8,
        'xss': 6.1,
        'csrf': 5.4,
        'information_disclosure': 4.3
    }
    
    base_score = base_scores.get(vulnerability_type.lower(), 5.0)
    
    # Adjust based on impact
    impact_multipliers = {
        'high': 1.0,
        'medium': 0.8,
        'low': 0.6
    }
    
    exploitability_multipliers = {
        'easy': 1.0,
        'medium': 0.9,
        'hard': 0.7
    }
    
    final_score = base_score * impact_multipliers.get(impact.lower(), 0.8) * exploitability_multipliers.get(exploitability.lower(), 0.9)
    final_score = min(10.0, max(0.0, final_score))
    
    # Generate basic CVSS vector
    vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    
    return round(final_score, 1), vector

def validate_vulnerability_data(vulnerability: Vulnerability) -> Tuple[bool, List[str]]:
    """Validate vulnerability data before submission"""
    errors = []
    
    # Required fields
    if not vulnerability.title or len(vulnerability.title.strip()) < 10:
        errors.append("Title must be at least 10 characters")
    
    if not vulnerability.description or len(vulnerability.description.strip()) < 50:
        errors.append("Description must be at least 50 characters")
    
    if not vulnerability.proof_of_concept or len(vulnerability.proof_of_concept.strip()) < 20:
        errors.append("Proof of concept must be at least 20 characters")
    
    # Severity validation
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if vulnerability.severity.lower() not in valid_severities:
        errors.append(f"Severity must be one of: {', '.join(valid_severities)}")
    
    # URL validation
    if vulnerability.affected_url:
        url_pattern = re.compile(r'^https?://[\w\-\.]+(:\d+)?(/.*)?$')
        if not url_pattern.match(vulnerability.affected_url):
            errors.append("Affected URL must be a valid HTTP/HTTPS URL")
    
    # CVSS validation
    if vulnerability.cvss_score is not None:
        if not (0.0 <= vulnerability.cvss_score <= 10.0):
            errors.append("CVSS score must be between 0.0 and 10.0")
    
    return len(errors) == 0, errors
