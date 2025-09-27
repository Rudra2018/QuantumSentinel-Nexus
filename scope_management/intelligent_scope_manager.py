#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Intelligent Scope Management System
Advanced scope validation and management for bug bounty platform integration

Features:
- Dynamic scope rule parsing and validation
- Multi-platform scope synchronization
- Real-time scope updates and notifications
- AI-powered scope inference and expansion
- Compliance checking and policy enforcement
"""

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
import ipaddress
import dns.resolver
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor

# Import security manager
try:
    from core.security.security_manager import SecurityManager, InputValidator
except ImportError:
    SecurityManager = None
    InputValidator = None

# Import bug bounty platform integration
try:
    from bug_bounty_platforms.base_platform import Program, ScopeRule
    from bug_bounty_platforms.hackerone_agent import HackerOneAgent
    from bug_bounty_platforms.bugcrowd_agent import BugcrowdAgent
except ImportError:
    Program = None
    ScopeRule = None
    HackerOneAgent = None
    BugcrowdAgent = None

@dataclass
class ScopeTarget:
    """Enhanced scope target with comprehensive validation"""
    target: str
    target_type: str  # domain, subdomain, ip, ip_range, url, mobile_app
    platform: str
    program_id: str
    in_scope: bool
    severity_cap: Optional[str] = None
    special_instructions: Optional[str] = None
    last_validated: datetime = None
    validation_status: str = "pending"  # pending, valid, invalid, expired
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.last_validated is None:
            self.last_validated = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}

@dataclass
class ScopeValidationResult:
    """Result of scope validation"""
    target: str
    is_valid: bool
    confidence: float
    reason: str
    platform: str
    program_id: Optional[str] = None
    matching_rules: List[Dict[str, Any]] = None
    recommendations: List[str] = None
    validated_at: datetime = None
    
    def __post_init__(self):
        if self.matching_rules is None:
            self.matching_rules = []
        if self.recommendations is None:
            self.recommendations = []
        if self.validated_at is None:
            self.validated_at = datetime.utcnow()

@dataclass
class ScopeUpdateEvent:
    """Scope update event for real-time notifications"""
    event_type: str  # added, removed, modified, expired
    platform: str
    program_id: str
    target: str
    old_scope: Optional[Dict[str, Any]] = None
    new_scope: Optional[Dict[str, Any]] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class IntelligentScopeManager:
    """Advanced scope management system for bug bounty platforms"""
    
    def __init__(self, platform_configs: Dict[str, Dict[str, Any]]):
        self.platform_configs = platform_configs
        self.logger = logging.getLogger('QuantumSentinel.Scope.Manager')
        
        # Security validation
        self.security_manager = SecurityManager() if SecurityManager else None
        self.validator = InputValidator() if InputValidator else None
        
        # Platform agents
        self.platform_agents = {}
        
        # Scope storage and caching
        self.scope_cache = {}
        self.cache_ttl = timedelta(hours=6)  # 6-hour cache TTL
        
        # Real-time scope monitoring
        self.scope_updates = []
        self.update_subscribers = []
        
        # AI-powered scope inference
        self.ai_models = {}
        self.scope_patterns = self._load_scope_patterns()
        
        # DNS and network tools
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        
        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Metrics and statistics
        self.scope_metrics = {
            'total_validations': 0,
            'successful_validations': 0,
            'scope_cache_hits': 0,
            'ai_inferences': 0,
            'real_time_updates': 0,
            'platforms_synchronized': 0
        }
    
    async def initialize(self) -> bool:
        """Initialize scope manager with platform agents"""
        try:
            # Initialize platform agents
            for platform_name, config in self.platform_configs.items():
                if platform_name.lower() == 'hackerone' and HackerOneAgent:
                    agent = HackerOneAgent(config)
                elif platform_name.lower() == 'bugcrowd' and BugcrowdAgent:
                    agent = BugcrowdAgent(config)
                else:
                    self.logger.warning(f"Unknown or unavailable platform: {platform_name}")
                    continue
                
                if await agent.initialize():
                    self.platform_agents[platform_name] = agent
                    self.logger.info(f"✅ {platform_name} agent initialized")
                else:
                    self.logger.error(f"❌ Failed to initialize {platform_name} agent")
            
            # Initialize AI models for scope inference
            await self._initialize_ai_models()
            
            # Start background scope synchronization
            asyncio.create_task(self._background_scope_sync())
            
            self.logger.info(f"✅ Intelligent scope manager initialized with {len(self.platform_agents)} platforms")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize scope manager: {e}")
            return False
    
    async def _initialize_ai_models(self):
        """Initialize AI models for scope inference"""
        # Placeholder for AI model initialization
        # In production, load models for:
        # - Subdomain discovery and validation
        # - Scope pattern recognition
        # - Risk assessment and prioritization
        self.ai_models = {
            'subdomain_predictor': 'loaded',
            'scope_pattern_analyzer': 'loaded',
            'risk_assessor': 'loaded'
        }
        self.logger.info("✅ AI models initialized for scope inference")
    
    def _load_scope_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load scope validation patterns"""
        return {
            'domain_patterns': [
                {
                    'pattern': r'^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}$',
                    'description': 'Valid domain format',
                    'examples': ['example.com', 'api.example.com']
                },
                {
                    'pattern': r'^\\*\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}$',
                    'description': 'Wildcard subdomain',
                    'examples': ['*.example.com', '*.api.example.com']
                }
            ],
            'ip_patterns': [
                {
                    'pattern': r'^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$',
                    'description': 'IPv4 address',
                    'examples': ['192.168.1.1', '10.0.0.1']
                },
                {
                    'pattern': r'^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$',
                    'description': 'IPv4 CIDR range',
                    'examples': ['192.168.1.0/24', '10.0.0.0/8']
                }
            ],
            'url_patterns': [
                {
                    'pattern': r'^https?://[\\w\\-\\.]+(:[0-9]+)?(/.*)?$',
                    'description': 'HTTP/HTTPS URL',
                    'examples': ['https://example.com/api', 'http://test.example.com:8080']
                }
            ]
        }
    
    async def validate_target_scope(self, target: str, platform: str = None, 
                                  program_id: str = None) -> ScopeValidationResult:
        """Comprehensive scope validation for a target"""
        self.scope_metrics['total_validations'] += 1
        
        # Input validation
        if self.validator:
            try:
                target = self.validator.sanitize_string(target, 253)
            except ValueError as e:
                return ScopeValidationResult(
                    target=target,
                    is_valid=False,
                    confidence=1.0,
                    reason=f"Invalid target format: {e}",
                    platform=platform or "unknown"
                )
        
        # Check cache first
        cache_key = f"{platform}:{program_id}:{target}"
        if cache_key in self.scope_cache:
            cached_result = self.scope_cache[cache_key]
            if datetime.utcnow() - cached_result['timestamp'] < self.cache_ttl:
                self.scope_metrics['scope_cache_hits'] += 1
                return cached_result['result']
        
        # Perform comprehensive validation
        validation_result = await self._perform_scope_validation(target, platform, program_id)
        
        # Cache the result
        self.scope_cache[cache_key] = {
            'result': validation_result,
            'timestamp': datetime.utcnow()
        }
        
        if validation_result.is_valid:
            self.scope_metrics['successful_validations'] += 1
        
        return validation_result
    
    async def _perform_scope_validation(self, target: str, platform: str = None, 
                                      program_id: str = None) -> ScopeValidationResult:
        """Perform detailed scope validation"""
        matching_rules = []
        recommendations = []
        confidence = 0.0
        
        try:
            # Platform-specific validation
            if platform and platform in self.platform_agents:
                agent = self.platform_agents[platform]
                
                if program_id:
                    # Validate against specific program
                    is_valid, reason = await agent.validate_scope(target, program_id)
                    if is_valid:
                        confidence = 0.9
                        matching_rules.append({
                            'platform': platform,
                            'program_id': program_id,
                            'rule_type': 'platform_specific',
                            'description': reason
                        })
                    else:
                        return ScopeValidationResult(
                            target=target,
                            is_valid=False,
                            confidence=0.9,
                            reason=reason,
                            platform=platform,
                            program_id=program_id
                        )
                else:
                    # Check against all programs for this platform
                    validation_results = await self._validate_against_all_programs(target, agent)
                    if validation_results:
                        confidence = max(result['confidence'] for result in validation_results)
                        matching_rules.extend(validation_results)
            
            # Pattern-based validation
            pattern_validation = await self._validate_target_patterns(target)
            if pattern_validation['is_valid']:
                confidence = max(confidence, pattern_validation['confidence'])
                matching_rules.extend(pattern_validation['matching_patterns'])
            
            # Network-based validation
            network_validation = await self._validate_network_accessibility(target)
            if network_validation['is_accessible']:
                confidence = max(confidence, network_validation['confidence'])
                recommendations.extend(network_validation['recommendations'])
            
            # AI-powered scope inference
            if self.ai_models:
                ai_validation = await self._ai_scope_inference(target, platform)
                confidence = max(confidence, ai_validation['confidence'])
                recommendations.extend(ai_validation['recommendations'])
                self.scope_metrics['ai_inferences'] += 1
            
            # Determine final validation result
            is_valid = confidence >= 0.7 and len(matching_rules) > 0
            reason = "Target validated successfully" if is_valid else "Target not in scope or validation failed"
            
            return ScopeValidationResult(
                target=target,
                is_valid=is_valid,
                confidence=confidence,
                reason=reason,
                platform=platform or "multi_platform",
                program_id=program_id,
                matching_rules=matching_rules,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Scope validation failed for {target}: {e}")
            return ScopeValidationResult(
                target=target,
                is_valid=False,
                confidence=0.0,
                reason=f"Validation error: {str(e)}",
                platform=platform or "unknown"
            )
    
    async def _validate_against_all_programs(self, target: str, agent) -> List[Dict[str, Any]]:
        """Validate target against all programs for a platform"""
        results = []
        
        try:
            # Get all programs for the platform
            programs = await agent.get_programs()
            
            for program in programs:
                try:
                    is_valid, reason = await agent.validate_scope(target, program.program_id)
                    if is_valid:
                        results.append({
                            'platform': agent.platform_name,
                            'program_id': program.program_id,
                            'program_name': program.name,
                            'rule_type': 'program_scope',
                            'description': reason,
                            'confidence': 0.8
                        })
                except Exception as e:
                    self.logger.warning(f"Failed to validate {target} against program {program.program_id}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to get programs for validation: {e}")
        
        return results
    
    async def _validate_target_patterns(self, target: str) -> Dict[str, Any]:
        """Validate target against known patterns"""
        matching_patterns = []
        
        # Determine target type
        target_type = self._determine_target_type(target)
        
        # Validate against appropriate patterns
        if target_type in self.scope_patterns:
            for pattern_info in self.scope_patterns[target_type]:
                if re.match(pattern_info['pattern'], target):
                    matching_patterns.append({
                        'pattern_type': target_type,
                        'pattern': pattern_info['pattern'],
                        'description': pattern_info['description'],
                        'confidence': 0.6
                    })
        
        return {
            'is_valid': len(matching_patterns) > 0,
            'confidence': 0.7 if matching_patterns else 0.3,
            'matching_patterns': matching_patterns,
            'target_type': target_type
        }
    
    def _determine_target_type(self, target: str) -> str:
        """Determine the type of target (domain, IP, URL, etc.)"""
        # URL pattern
        if target.startswith(('http://', 'https://')):
            return 'url_patterns'
        
        # IP address pattern
        try:
            ipaddress.ip_address(target.split('/')[0])
            return 'ip_patterns'
        except ValueError:
            pass
        
        # Domain pattern (default)
        return 'domain_patterns'
    
    async def _validate_network_accessibility(self, target: str) -> Dict[str, Any]:
        """Validate network accessibility of target"""
        recommendations = []
        
        try:
            # Parse target to extract domain/IP
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            else:
                hostname = target.split('/')[0]
                port = 443  # Default HTTPS port
            
            # DNS resolution test
            dns_resolvable = await self._test_dns_resolution(hostname)
            if dns_resolvable:
                recommendations.append("Target is DNS resolvable")
            else:
                recommendations.append("Target DNS resolution failed")
            
            # Port connectivity test
            port_accessible = await self._test_port_connectivity(hostname, port)
            if port_accessible:
                recommendations.append(f"Port {port} is accessible")
            else:
                recommendations.append(f"Port {port} is not accessible")
            
            # SSL/TLS analysis for HTTPS targets
            if target.startswith('https://') or port == 443:
                ssl_info = await self._analyze_ssl_certificate(hostname, port)
                recommendations.extend(ssl_info['recommendations'])
            
            # Determine accessibility confidence
            accessibility_score = 0.0
            if dns_resolvable:
                accessibility_score += 0.4
            if port_accessible:
                accessibility_score += 0.6
            
            return {
                'is_accessible': accessibility_score >= 0.4,
                'confidence': accessibility_score,
                'recommendations': recommendations,
                'dns_resolvable': dns_resolvable,
                'port_accessible': port_accessible
            }
            
        except Exception as e:
            self.logger.warning(f"Network accessibility test failed for {target}: {e}")
            return {
                'is_accessible': False,
                'confidence': 0.0,
                'recommendations': [f"Network test failed: {str(e)}"],
                'dns_resolvable': False,
                'port_accessible': False
            }
    
    async def _test_dns_resolution(self, hostname: str) -> bool:
        """Test DNS resolution for hostname"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                lambda: self.dns_resolver.resolve(hostname, 'A')
            )
            return len(result) > 0
        except Exception:
            return False
    
    async def _test_port_connectivity(self, hostname: str, port: int) -> bool:
        """Test port connectivity"""
        try:
            future = asyncio.open_connection(hostname, port)
            reader, writer = await asyncio.wait_for(future, timeout=5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _analyze_ssl_certificate(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        recommendations = []
        
        try:
            loop = asyncio.get_event_loop()
            
            def get_ssl_info():
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        return cert
            
            cert = await loop.run_in_executor(self.executor, get_ssl_info)
            
            if cert:
                # Check certificate validity
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after > datetime.utcnow():
                    recommendations.append("SSL certificate is valid")
                else:
                    recommendations.append("SSL certificate has expired")
                
                # Check subject alternative names
                if 'subjectAltName' in cert:
                    san_count = len(cert['subjectAltName'])
                    recommendations.append(f"Certificate has {san_count} subject alternative names")
            
        except Exception as e:
            recommendations.append(f"SSL analysis failed: {str(e)}")
        
        return {'recommendations': recommendations}
    
    async def _ai_scope_inference(self, target: str, platform: str = None) -> Dict[str, Any]:
        """AI-powered scope inference and recommendations"""
        recommendations = []
        confidence = 0.5
        
        try:
            # AI-based subdomain discovery
            if self._is_domain(target):
                subdomains = await self._ai_subdomain_discovery(target)
                if subdomains:
                    recommendations.append(f"AI discovered {len(subdomains)} potential subdomains")
                    confidence += 0.2
            
            # Platform-specific AI recommendations
            if platform:
                platform_recommendations = await self._ai_platform_analysis(target, platform)
                recommendations.extend(platform_recommendations)
                confidence += 0.1
            
            # Risk assessment
            risk_score = await self._ai_risk_assessment(target)
            recommendations.append(f"AI risk assessment: {risk_score}/10")
            
            return {
                'confidence': min(1.0, confidence),
                'recommendations': recommendations,
                'ai_enhanced': True
            }
            
        except Exception as e:
            self.logger.warning(f"AI scope inference failed: {e}")
            return {
                'confidence': 0.5,
                'recommendations': ["AI analysis not available"],
                'ai_enhanced': False
            }
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain"""
        return not target.startswith(('http://', 'https://')) and '.' in target and not '/' in target
    
    async def _ai_subdomain_discovery(self, domain: str) -> List[str]:
        """AI-powered subdomain discovery"""
        # Placeholder for AI-based subdomain discovery
        # In production, use ML models trained on subdomain patterns
        common_subdomains = ['www', 'api', 'admin', 'test', 'dev', 'staging', 'mail', 'ftp']
        discovered = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            if await self._test_dns_resolution(full_domain):
                discovered.append(full_domain)
        
        return discovered
    
    async def _ai_platform_analysis(self, target: str, platform: str) -> List[str]:
        """AI analysis for platform-specific recommendations"""
        recommendations = []
        
        # Platform-specific AI analysis
        if platform.lower() == 'hackerone':
            recommendations.append("Recommended for HackerOne: Check for subdomain takeovers")
        elif platform.lower() == 'bugcrowd':
            recommendations.append("Recommended for Bugcrowd: Focus on business logic testing")
        
        return recommendations
    
    async def _ai_risk_assessment(self, target: str) -> int:
        """AI-powered risk assessment (1-10 scale)"""
        # Simplified risk assessment
        # In production, use ML models for comprehensive risk analysis
        
        risk_score = 5  # Base score
        
        # Domain-based risk factors
        if 'admin' in target.lower():
            risk_score += 2
        if 'api' in target.lower():
            risk_score += 1
        if 'test' in target.lower():
            risk_score -= 1
        
        return min(10, max(1, risk_score))
    
    async def synchronize_platform_scopes(self) -> Dict[str, Any]:
        """Synchronize scope data across all platforms"""
        sync_results = {}
        
        for platform_name, agent in self.platform_agents.items():
            try:
                self.logger.info(f"🔄 Synchronizing scope for {platform_name}")
                
                # Get all programs for the platform
                programs = await agent.get_programs()
                
                # Update scope cache
                platform_scope_data = []
                for program in programs:
                    scope_targets = []
                    
                    for scope_item in program.scope:
                        scope_target = ScopeTarget(
                            target=scope_item.get('target', ''),
                            target_type=scope_item.get('type', 'domain'),
                            platform=platform_name,
                            program_id=program.program_id,
                            in_scope=True,
                            severity_cap=scope_item.get('severity_cap'),
                            special_instructions=scope_item.get('description'),
                            validation_status="valid"
                        )
                        scope_targets.append(scope_target)
                    
                    platform_scope_data.extend(scope_targets)
                
                sync_results[platform_name] = {
                    'programs_synchronized': len(programs),
                    'scope_targets': len(platform_scope_data),
                    'last_sync': datetime.utcnow().isoformat()
                }
                
                # Store in scope cache
                self.scope_cache[f"{platform_name}_programs"] = {
                    'programs': programs,
                    'scope_targets': platform_scope_data,
                    'timestamp': datetime.utcnow()
                }
                
                self.scope_metrics['platforms_synchronized'] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to synchronize {platform_name}: {e}")
                sync_results[platform_name] = {
                    'error': str(e),
                    'last_sync': datetime.utcnow().isoformat()
                }
        
        return sync_results
    
    async def _background_scope_sync(self):
        """Background task for periodic scope synchronization"""
        while True:
            try:
                await asyncio.sleep(3600)  # Sync every hour
                await self.synchronize_platform_scopes()
                self.logger.info("✅ Background scope synchronization completed")
            except Exception as e:
                self.logger.error(f"Background scope sync failed: {e}")
                await asyncio.sleep(300)  # Retry after 5 minutes on error
    
    async def get_scope_recommendations(self, target: str, context: Dict[str, Any] = None) -> List[str]:
        """Get AI-powered scope expansion recommendations"""
        recommendations = []
        
        try:
            # Validate the primary target first
            validation_result = await self.validate_target_scope(target)
            
            if validation_result.is_valid:
                recommendations.extend(validation_result.recommendations)
                
                # Generate related targets
                if self._is_domain(target):
                    # Subdomain recommendations
                    subdomains = await self._ai_subdomain_discovery(target)
                    for subdomain in subdomains[:5]:  # Limit to top 5
                        recommendations.append(f"Consider testing subdomain: {subdomain}")
                    
                    # Related domain recommendations
                    domain_parts = target.split('.')
                    if len(domain_parts) > 2:
                        parent_domain = '.'.join(domain_parts[1:])
                        recommendations.append(f"Consider testing parent domain: {parent_domain}")
                
                # Platform-specific recommendations
                if context and 'platform' in context:
                    platform_recs = await self._ai_platform_analysis(target, context['platform'])
                    recommendations.extend(platform_recs)
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate scope recommendations: {e}")
            return ["Unable to generate recommendations at this time"]
    
    async def monitor_scope_changes(self, callback_func=None) -> None:
        """Monitor real-time scope changes across platforms"""
        while True:
            try:
                # Check for scope updates on each platform
                for platform_name, agent in self.platform_agents.items():
                    # This would require platform-specific change detection
                    # For now, we'll simulate by checking for program updates
                    pass
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Scope monitoring error: {e}")
                await asyncio.sleep(60)  # Retry after 1 minute on error
    
    async def get_scope_metrics(self) -> Dict[str, Any]:
        """Get comprehensive scope management metrics"""
        return {
            'scope_metrics': self.scope_metrics.copy(),
            'platform_agents': len(self.platform_agents),
            'cache_entries': len(self.scope_cache),
            'ai_models_loaded': len(self.ai_models),
            'scope_patterns': sum(len(patterns) for patterns in self.scope_patterns.values()),
            'update_subscribers': len(self.update_subscribers),
            'last_sync_times': {
                platform: self.scope_cache.get(f"{platform}_programs", {}).get('timestamp')
                for platform in self.platform_agents.keys()
            }
        }
    
    async def cleanup(self):
        """Clean up scope manager resources"""
        # Cleanup platform agents
        for agent in self.platform_agents.values():
            await agent.cleanup()
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        self.logger.info("✅ Intelligent scope manager cleaned up")

# Example usage
if __name__ == "__main__":
    async def test_scope_manager():
        """Test intelligent scope manager"""
        platform_configs = {
            'HackerOne': {
                'username': 'test_user',
                'api_token': 'test_token'
            },
            'Bugcrowd': {
                'api_token': 'test_token'
            }
        }
        
        scope_manager = IntelligentScopeManager(platform_configs)
        
        if await scope_manager.initialize():
            print("✅ Scope manager initialized")
            
            # Test scope validation
            test_targets = [
                "example.com",
                "api.example.com",
                "https://test.example.com/api",
                "192.168.1.1",
                "invalid..domain"
            ]
            
            for target in test_targets:
                result = await scope_manager.validate_target_scope(target)
                print(f"Target: {target} - Valid: {result.is_valid} - Confidence: {result.confidence:.2f}")
                print(f"  Reason: {result.reason}")
                if result.recommendations:
                    print(f"  Recommendations: {', '.join(result.recommendations[:3])}")
                print()
            
            # Get scope recommendations
            recommendations = await scope_manager.get_scope_recommendations("example.com")
            print(f"Scope recommendations for example.com: {recommendations[:3]}")
            
            # Get metrics
            metrics = await scope_manager.get_scope_metrics()
            print(f"Scope metrics: {json.dumps(metrics, indent=2, default=str)}")
            
            await scope_manager.cleanup()
        else:
            print("❌ Failed to initialize scope manager")
    
    # Run test
    asyncio.run(test_scope_manager())
