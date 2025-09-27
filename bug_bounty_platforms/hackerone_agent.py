#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - HackerOne Platform Agent
Specialized agent for HackerOne bug bounty platform integration

Features:
- Program discovery and scope validation
- Automated vulnerability submission
- Policy-compliant testing coordination
- Real-time program updates
"""

import asyncio
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin

from .base_platform import BasePlatformAgent, Program, Vulnerability, SubmissionResult, ScopeRule

class HackerOneAgent(BasePlatformAgent):
    """HackerOne platform integration agent"""
    
    def __init__(self, api_config: Dict[str, Any]):
        super().__init__("HackerOne", api_config)
        
        # HackerOne specific configuration
        self.base_url = "https://api.hackerone.com/v1/"
        self.username = api_config.get('username')
        self.api_token = api_config.get('api_token')
        
        # HackerOne rate limits
        self.rate_limits.update({
            'requests_per_minute': 100,
            'requests_per_hour': 3600,
            'concurrent_requests': 10
        })
        
        # HackerOne specific metrics
        self.h1_metrics = {
            'programs_discovered': 0,
            'submissions_accepted': 0,
            'submissions_rejected': 0,
            'bounties_earned': 0.0,
            'reputation_points': 0
        }
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get HackerOne API headers"""
        if not self.username or not self.api_token:
            return {}
        
        # Basic auth header for HackerOne API
        credentials = f"{self.username}:{self.api_token}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        return {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'QuantumSentinel-Nexus/6.0 (Security Research)'
        }
    
    async def _authenticate(self) -> bool:
        """Authenticate with HackerOne API"""
        if not self.username or not self.api_token:
            self.logger.error("HackerOne username and API token required")
            return False
        
        try:
            # Test authentication with a simple API call
            success, response = await self._make_request('GET', urljoin(self.base_url, 'me'))
            if success:
                user_data = response.get('data', {})
                attributes = user_data.get('attributes', {})
                self.logger.info(f"Authenticated as: {attributes.get('username', 'Unknown')}")
                
                # Update metrics if available
                self.h1_metrics['reputation_points'] = attributes.get('reputation', 0)
                return True
            else:
                self.logger.error(f"Authentication failed: {response}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def get_programs(self, filters: Optional[Dict[str, Any]] = None) -> List[Program]:
        """Fetch available HackerOne programs"""
        programs = []
        
        try:
            # Build query parameters
            params = {
                'page[size]': 100,
                'sort': 'launched_at',
                'filter[state]': 'public_mode'
            }
            
            if filters:
                if filters.get('accepts_submissions'):
                    params['filter[submission_state]'] = 'open'
                if filters.get('minimum_bounty'):
                    params['filter[offers_bounties]'] = 'true'
            
            # Fetch programs with pagination
            page = 1
            while True:
                params['page[number]'] = page
                
                success, response = await self._make_request(
                    'GET',
                    urljoin(self.base_url, 'programs'),
                    params=params
                )
                
                if not success:
                    self.logger.error(f"Failed to fetch programs page {page}: {response}")
                    break
                
                programs_data = response.get('data', [])
                if not programs_data:
                    break
                
                for program_data in programs_data:
                    try:
                        program = self._parse_program_data(program_data)
                        if program:
                            programs.append(program)
                            self.program_cache[program.program_id] = program
                    except Exception as e:
                        self.logger.warning(f"Failed to parse program data: {e}")
                
                # Check if there are more pages
                links = response.get('links', {})
                if not links.get('next'):
                    break
                
                page += 1
                if page > 50:  # Safety limit
                    break
            
            self.h1_metrics['programs_discovered'] = len(programs)
            self.logger.info(f"Discovered {len(programs)} HackerOne programs")
            
        except Exception as e:
            self.logger.error(f"Error fetching programs: {e}")
        
        return programs
    
    async def get_program_details(self, program_id: str) -> Optional[Program]:
        """Get detailed information about a specific HackerOne program"""
        # Check cache first
        if program_id in self.program_cache:
            cached_program = self.program_cache[program_id]
            if datetime.utcnow() - cached_program.last_updated < self.cache_ttl:
                return cached_program
        
        try:
            success, response = await self._make_request(
                'GET',
                urljoin(self.base_url, f'programs/{program_id}')
            )
            
            if success:
                program_data = response.get('data', {})
                program = self._parse_program_data(program_data)
                if program:
                    self.program_cache[program_id] = program
                return program
            else:
                self.logger.error(f"Failed to fetch program {program_id}: {response}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error fetching program {program_id}: {e}")
            return None
    
    def _parse_program_data(self, program_data: Dict[str, Any]) -> Optional[Program]:
        """Parse HackerOne program data into Program object"""
        try:
            attributes = program_data.get('attributes', {})
            relationships = program_data.get('relationships', {})
            
            # Parse scope
            scope = self._parse_scope_from_attributes(attributes)
            out_of_scope = self._parse_out_of_scope_from_attributes(attributes)
            
            # Parse rewards
            rewards = {
                'offers_bounties': attributes.get('offers_bounties', False),
                'offers_swag': attributes.get('offers_swag', False),
                'minimum_bounty': attributes.get('base_bounty', 0),
                'currency': 'USD'
            }
            
            # Parse submission guidelines
            submission_guidelines = {
                'policy': attributes.get('policy', ''),
                'submission_requirements': attributes.get('submission_requirements', ''),
                'response_efficiency': attributes.get('response_efficiency_percentage', 0)
            }
            
            # Parse metrics
            metrics = {
                'total_reports': attributes.get('reports_count', 0),
                'resolved_reports': attributes.get('resolved_reports_count', 0),
                'response_efficiency': attributes.get('response_efficiency_percentage', 0),
                'average_response_time': attributes.get('average_time_to_first_program_response', 0),
                'last_report_at': attributes.get('last_report_at')
            }
            
            return Program(
                platform="HackerOne",
                program_id=program_data.get('id', ''),
                name=attributes.get('name', ''),
                company=attributes.get('handle', ''),
                scope=scope,
                out_of_scope=out_of_scope,
                rewards=rewards,
                submission_guidelines=submission_guidelines,
                last_updated=datetime.utcnow(),
                status='active' if attributes.get('submission_state') == 'open' else 'closed',
                metrics=metrics
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing program data: {e}")
            return None
    
    def _parse_scope_from_attributes(self, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse scope from program attributes"""
        scope = []
        
        # HackerOne stores scope in structured_scope
        structured_scope = attributes.get('structured_scope', {})
        
        for scope_item in structured_scope.get('data', []):
            scope_attributes = scope_item.get('attributes', {})
            
            scope_entry = {
                'type': scope_attributes.get('asset_type', 'domain'),
                'target': scope_attributes.get('asset_identifier', ''),
                'description': scope_attributes.get('instruction', ''),
                'severity_cap': scope_attributes.get('max_severity'),
                'testing_allowed': scope_attributes.get('eligible_for_submission', True)
            }
            
            if scope_entry['target']:  # Only add if target is specified
                scope.append(scope_entry)
        
        return scope
    
    def _parse_out_of_scope_from_attributes(self, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse out-of-scope from program attributes"""
        # HackerOne typically includes out-of-scope in policy text
        # This would need more sophisticated parsing in production
        return []
    
    async def validate_scope(self, target: str, program_id: str) -> Tuple[bool, str]:
        """Validate if target is within HackerOne program scope"""
        if not self._validate_target_format(target):
            return False, "Invalid target format"
        
        program = await self.get_program_details(program_id)
        if not program:
            return False, "Program not found"
        
        if program.status != 'active':
            return False, f"Program is {program.status}, not accepting submissions"
        
        # Parse scope rules
        scope_rules = self._parse_scope_rules(program.scope)
        
        # Check if target matches any scope rule
        for rule in scope_rules:
            if self._match_scope_rule(target, rule):
                if not rule.testing_allowed:
                    return False, f"Testing not allowed for {target} (special restrictions)"
                return True, f"Target in scope: {rule.description}"
        
        return False, "Target not found in program scope"
    
    async def submit_finding(self, vulnerability: Vulnerability, program_id: str) -> SubmissionResult:
        """Submit vulnerability finding to HackerOne"""
        try:
            # Validate vulnerability data
            from .base_platform import validate_vulnerability_data
            is_valid, errors = validate_vulnerability_data(vulnerability)
            if not is_valid:
                return SubmissionResult(
                    submission_id="",
                    status="rejected",
                    platform_response={"errors": errors},
                    submission_date=datetime.utcnow(),
                    error_message="Validation failed: " + "; ".join(errors)
                )
            
            # Validate scope
            in_scope, scope_message = await self.validate_scope(vulnerability.affected_url, program_id)
            if not in_scope:
                return SubmissionResult(
                    submission_id="",
                    status="rejected",
                    platform_response={"error": scope_message},
                    submission_date=datetime.utcnow(),
                    error_message=f"Out of scope: {scope_message}"
                )
            
            # Format submission data for HackerOne API
            submission_data = {
                "data": {
                    "type": "report",
                    "attributes": {
                        "title": vulnerability.title,
                        "vulnerability_information": vulnerability.description,
                        "impact": vulnerability.impact,
                        "severity_rating": vulnerability.severity.capitalize(),
                        "proof_of_concept": vulnerability.proof_of_concept,
                        "suggested_fix": vulnerability.remediation
                    },
                    "relationships": {
                        "program": {
                            "data": {
                                "type": "program",
                                "id": program_id
                            }
                        }
                    }
                }
            }
            
            # Submit to HackerOne
            success, response = await self._make_request(
                'POST',
                urljoin(self.base_url, 'reports'),
                json=submission_data
            )
            
            if success:
                report_data = response.get('data', {})
                submission_id = report_data.get('id', '')
                
                self.h1_metrics['submissions_made'] += 1
                
                return SubmissionResult(
                    submission_id=submission_id,
                    status="submitted",
                    platform_response=response,
                    submission_date=datetime.utcnow(),
                    estimated_response_time=timedelta(days=5)  # HackerOne typical response time
                )
            else:
                return SubmissionResult(
                    submission_id="",
                    status="failed",
                    platform_response=response if isinstance(response, dict) else {"error": str(response)},
                    submission_date=datetime.utcnow(),
                    error_message=str(response)
                )
                
        except Exception as e:
            self.logger.error(f"Error submitting finding: {e}")
            return SubmissionResult(
                submission_id="",
                status="error",
                platform_response={"error": str(e)},
                submission_date=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_submission_status(self, submission_id: str) -> Dict[str, Any]:
        """Check status of submitted vulnerability report"""
        try:
            success, response = await self._make_request(
                'GET',
                urljoin(self.base_url, f'reports/{submission_id}')
            )
            
            if success:
                report_data = response.get('data', {})
                attributes = report_data.get('attributes', {})
                
                return {
                    'submission_id': submission_id,
                    'status': attributes.get('state', 'unknown'),
                    'title': attributes.get('title', ''),
                    'severity': attributes.get('severity_rating', ''),
                    'created_at': attributes.get('created_at'),
                    'updated_at': attributes.get('last_activity_at'),
                    'bounty_awarded': attributes.get('bounty_awarded_at') is not None,
                    'bounty_amount': attributes.get('total_bounty_amount', 0),
                    'reporter_reputation': attributes.get('reporter', {}).get('reputation', 0)
                }
            else:
                return {
                    'submission_id': submission_id,
                    'status': 'error',
                    'error': str(response)
                }
                
        except Exception as e:
            self.logger.error(f"Error checking submission status: {e}")
            return {
                'submission_id': submission_id,
                'status': 'error',
                'error': str(e)
            }
    
    async def _health_check_request(self) -> Tuple[bool, Any]:
        """HackerOne health check"""
        return await self._make_request('GET', urljoin(self.base_url, 'me'))
    
    async def get_hackerone_stats(self) -> Dict[str, Any]:
        """Get HackerOne-specific statistics"""
        base_stats = await self.get_platform_stats()
        base_stats['hackerone_metrics'] = self.h1_metrics.copy()
        
        # Try to get current user statistics
        try:
            success, response = await self._make_request('GET', urljoin(self.base_url, 'me'))
            if success:
                user_data = response.get('data', {})
                attributes = user_data.get('attributes', {})
                
                base_stats['user_profile'] = {
                    'username': attributes.get('username'),
                    'reputation': attributes.get('reputation', 0),
                    'signal': attributes.get('signal', 0),
                    'impact': attributes.get('impact', 0),
                    'total_bounties': attributes.get('total_bounty_amount', 0)
                }
        except Exception as e:
            self.logger.warning(f"Could not fetch user profile: {e}")
        
        return base_stats
    
    async def get_leaderboard(self) -> Dict[str, Any]:
        """Get HackerOne leaderboard information"""
        try:
            success, response = await self._make_request(
                'GET',
                urljoin(self.base_url, 'hackers')
            )
            
            if success:
                return {
                    'leaderboard': response.get('data', []),
                    'updated_at': datetime.utcnow().isoformat()
                }
            else:
                return {'error': str(response)}
                
        except Exception as e:
            self.logger.error(f"Error fetching leaderboard: {e}")
            return {'error': str(e)}

# Example usage
if __name__ == "__main__":
    async def test_hackerone_agent():
        """Test HackerOne agent functionality"""
        config = {
            'username': 'your_username',
            'api_token': 'your_api_token'
        }
        
        agent = HackerOneAgent(config)
        
        # Initialize
        if await agent.initialize():
            print("✅ HackerOne agent initialized")
            
            # Get programs
            programs = await agent.get_programs({'accepts_submissions': True})
            print(f"Found {len(programs)} programs")
            
            # Get stats
            stats = await agent.get_hackerone_stats()
            print(f"Agent stats: {json.dumps(stats, indent=2, default=str)}")
            
            # Cleanup
            await agent.cleanup()
        else:
            print("❌ Failed to initialize HackerOne agent")
    
    # Run test
    asyncio.run(test_hackerone_agent())
