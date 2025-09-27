#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Bugcrowd Platform Agent
Specialized agent for Bugcrowd bug bounty platform integration

Features:
- Crowd-sourced program discovery
- Community-driven scope validation
- Collaborative vulnerability submission
- Real-time program engagement metrics
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin

from .base_platform import BasePlatformAgent, Program, Vulnerability, SubmissionResult, ScopeRule

class BugcrowdAgent(BasePlatformAgent):
    """Bugcrowd platform integration agent"""
    
    def __init__(self, api_config: Dict[str, Any]):
        super().__init__("Bugcrowd", api_config)
        
        # Bugcrowd specific configuration
        self.base_url = "https://api.bugcrowd.com/"
        self.api_token = api_config.get('api_token')
        
        # Bugcrowd rate limits
        self.rate_limits.update({
            'requests_per_minute': 50,
            'requests_per_hour': 2000,
            'concurrent_requests': 8
        })
        
        # Bugcrowd specific metrics
        self.bc_metrics = {
            'programs_discovered': 0,
            'crowd_validations': 0,
            'community_points': 0,
            'collaboration_score': 0.0
        }
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get Bugcrowd API headers"""
        if not self.api_token:
            return {}
        
        return {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'QuantumSentinel-Nexus/6.0 (Security Research)'
        }
    
    async def _authenticate(self) -> bool:
        """Authenticate with Bugcrowd API"""
        if not self.api_token:
            self.logger.error("Bugcrowd API token required")
            return False
        
        try:
            # Test authentication with user profile endpoint
            success, response = await self._make_request('GET', urljoin(self.base_url, 'me'))
            if success:
                user_data = response.get('user', {})
                self.logger.info(f"Authenticated as: {user_data.get('username', 'Unknown')}")
                
                # Update metrics if available
                self.bc_metrics['community_points'] = user_data.get('points', 0)
                self.bc_metrics['collaboration_score'] = user_data.get('reputation', 0.0)
                return True
            else:
                self.logger.error(f"Authentication failed: {response}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def get_programs(self, filters: Optional[Dict[str, Any]] = None) -> List[Program]:
        """Fetch available Bugcrowd programs"""
        programs = []
        
        try:
            # Build query parameters for Bugcrowd API
            params = {
                'limit': 100,
                'sort': 'launched_at',
                'filter[accepting_submissions]': 'true'
            }
            
            if filters:
                if filters.get('minimum_bounty'):
                    params['filter[offers_rewards]'] = 'true'
                if filters.get('program_type'):
                    params['filter[program_type]'] = filters['program_type']
            
            # Fetch programs with pagination
            offset = 0
            while True:
                params['offset'] = offset
                
                success, response = await self._make_request(
                    'GET',
                    urljoin(self.base_url, 'programs'),
                    params=params
                )
                
                if not success:
                    self.logger.error(f"Failed to fetch programs at offset {offset}: {response}")
                    break
                
                programs_data = response.get('programs', [])
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
                
                # Check if there are more programs
                if len(programs_data) < params['limit']:
                    break
                
                offset += params['limit']
                if offset > 5000:  # Safety limit
                    break
            
            self.bc_metrics['programs_discovered'] = len(programs)
            self.logger.info(f"Discovered {len(programs)} Bugcrowd programs")
            
        except Exception as e:
            self.logger.error(f"Error fetching programs: {e}")
        
        return programs
    
    async def get_program_details(self, program_id: str) -> Optional[Program]:
        """Get detailed information about a specific Bugcrowd program"""
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
                program_data = response.get('program', {})
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
        """Parse Bugcrowd program data into Program object"""
        try:
            # Parse scope from Bugcrowd format
            scope = self._parse_bugcrowd_scope(program_data.get('target_groups', []))
            out_of_scope = self._parse_bugcrowd_out_of_scope(program_data.get('out_of_scope', []))
            
            # Parse rewards
            rewards = {
                'offers_bounties': program_data.get('offers_bounties', False),
                'offers_kudos': program_data.get('offers_kudos', False),
                'minimum_bounty': program_data.get('min_bounty', 0),
                'maximum_bounty': program_data.get('max_bounty', 0),
                'currency': program_data.get('currency', 'USD')
            }
            
            # Parse submission guidelines
            submission_guidelines = {
                'policy': program_data.get('brief', ''),
                'submission_requirements': program_data.get('safe_harbor', ''),
                'response_efficiency': program_data.get('avg_response_time', 0)
            }
            
            # Parse metrics
            metrics = {
                'total_submissions': program_data.get('submissions_count', 0),
                'accepted_submissions': program_data.get('accepted_submissions_count', 0),
                'avg_response_time_days': program_data.get('avg_response_time', 0),
                'researcher_count': program_data.get('researcher_count', 0),
                'last_activity': program_data.get('updated_at')
            }
            
            return Program(
                platform="Bugcrowd",
                program_id=str(program_data.get('id', '')),
                name=program_data.get('name', ''),
                company=program_data.get('organization', {}).get('name', ''),
                scope=scope,
                out_of_scope=out_of_scope,
                rewards=rewards,
                submission_guidelines=submission_guidelines,
                last_updated=datetime.utcnow(),
                status='active' if program_data.get('accepting_submissions') else 'closed',
                metrics=metrics
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing program data: {e}")
            return None
    
    def _parse_bugcrowd_scope(self, target_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse scope from Bugcrowd target groups"""
        scope = []
        
        for group in target_groups:
            targets = group.get('targets', [])
            for target in targets:
                scope_entry = {
                    'type': target.get('category', 'other'),
                    'target': target.get('name', ''),
                    'description': target.get('description', ''),
                    'severity_cap': group.get('max_severity'),
                    'testing_allowed': target.get('in_scope', True)
                }
                
                if scope_entry['target']:  # Only add if target is specified
                    scope.append(scope_entry)
        
        return scope
    
    def _parse_bugcrowd_out_of_scope(self, out_of_scope_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse out-of-scope from Bugcrowd data"""
        out_of_scope = []
        
        for item in out_of_scope_data:
            out_of_scope_entry = {
                'type': item.get('category', 'other'),
                'target': item.get('name', ''),
                'description': item.get('description', ''),
                'reason': 'explicitly_excluded'
            }
            
            if out_of_scope_entry['target']:
                out_of_scope.append(out_of_scope_entry)
        
        return out_of_scope
    
    async def validate_scope(self, target: str, program_id: str) -> Tuple[bool, str]:
        """Validate if target is within Bugcrowd program scope"""
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
        
        # Check out-of-scope rules
        out_of_scope_rules = self._parse_scope_rules(program.out_of_scope)
        for rule in out_of_scope_rules:
            if self._match_scope_rule(target, rule):
                return False, f"Target explicitly out of scope: {rule.description}"
        
        return False, "Target not found in program scope"
    
    async def submit_finding(self, vulnerability: Vulnerability, program_id: str) -> SubmissionResult:
        """Submit vulnerability finding to Bugcrowd"""
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
            
            # Format submission data for Bugcrowd API
            submission_data = {
                "submission": {
                    "title": vulnerability.title,
                    "description": vulnerability.description,
                    "impact": vulnerability.impact,
                    "severity": self._map_severity_to_bugcrowd(vulnerability.severity),
                    "proof_of_concept": vulnerability.proof_of_concept,
                    "remediation_advice": vulnerability.remediation,
                    "url": vulnerability.affected_url,
                    "program_id": program_id,
                    "vulnerability_types": [vulnerability.vulnerability_type]
                }
            }
            
            # Add CVSS data if available
            if vulnerability.cvss_score:
                submission_data["submission"]["cvss_score"] = vulnerability.cvss_score
            if vulnerability.cvss_vector:
                submission_data["submission"]["cvss_vector"] = vulnerability.cvss_vector
            
            # Submit to Bugcrowd
            success, response = await self._make_request(
                'POST',
                urljoin(self.base_url, 'submissions'),
                json=submission_data
            )
            
            if success:
                submission_data_response = response.get('submission', {})
                submission_id = str(submission_data_response.get('id', ''))
                
                self.bc_metrics['submissions_made'] = self.bc_metrics.get('submissions_made', 0) + 1
                
                return SubmissionResult(
                    submission_id=submission_id,
                    status="submitted",
                    platform_response=response,
                    submission_date=datetime.utcnow(),
                    estimated_response_time=timedelta(days=7)  # Bugcrowd typical response time
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
    
    def _map_severity_to_bugcrowd(self, severity: str) -> str:
        """Map generic severity to Bugcrowd severity levels"""
        severity_mapping = {
            'critical': 'P1',
            'high': 'P2',
            'medium': 'P3',
            'low': 'P4',
            'info': 'P5'
        }
        return severity_mapping.get(severity.lower(), 'P3')
    
    async def check_submission_status(self, submission_id: str) -> Dict[str, Any]:
        """Check status of submitted vulnerability report"""
        try:
            success, response = await self._make_request(
                'GET',
                urljoin(self.base_url, f'submissions/{submission_id}')
            )
            
            if success:
                submission_data = response.get('submission', {})
                
                return {
                    'submission_id': submission_id,
                    'status': submission_data.get('state', 'unknown'),
                    'title': submission_data.get('title', ''),
                    'severity': submission_data.get('severity', ''),
                    'created_at': submission_data.get('submitted_at'),
                    'updated_at': submission_data.get('updated_at'),
                    'bounty_awarded': submission_data.get('bounty_amount', 0) > 0,
                    'bounty_amount': submission_data.get('bounty_amount', 0),
                    'kudos_awarded': submission_data.get('kudos_awarded', False),
                    'crowd_feedback': submission_data.get('crowd_feedback', [])
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
        """Bugcrowd health check"""
        return await self._make_request('GET', urljoin(self.base_url, 'me'))
    
    async def get_bugcrowd_stats(self) -> Dict[str, Any]:
        """Get Bugcrowd-specific statistics"""
        base_stats = await self.get_platform_stats()
        base_stats['bugcrowd_metrics'] = self.bc_metrics.copy()
        
        # Try to get current user statistics
        try:
            success, response = await self._make_request('GET', urljoin(self.base_url, 'me'))
            if success:
                user_data = response.get('user', {})
                
                base_stats['user_profile'] = {
                    'username': user_data.get('username'),
                    'points': user_data.get('points', 0),
                    'reputation': user_data.get('reputation', 0.0),
                    'rank': user_data.get('rank', 'N/A'),
                    'total_bounties': user_data.get('total_bounty_amount', 0),
                    'submissions_count': user_data.get('submissions_count', 0)
                }
        except Exception as e:
            self.logger.warning(f"Could not fetch user profile: {e}")
        
        return base_stats
    
    async def get_crowd_validation(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Get crowd validation for a vulnerability (Bugcrowd specific feature)"""
        try:
            # This would be a Bugcrowd-specific API call for crowd validation
            validation_data = {
                "vulnerability_type": vulnerability.vulnerability_type,
                "severity": vulnerability.severity,
                "affected_url": vulnerability.affected_url,
                "description": vulnerability.description[:200]  # Truncate for validation
            }
            
            success, response = await self._make_request(
                'POST',
                urljoin(self.base_url, 'crowd_validations'),
                json={"validation_request": validation_data}
            )
            
            if success:
                validation_result = response.get('validation', {})
                self.bc_metrics['crowd_validations'] += 1
                
                return {
                    'validation_score': validation_result.get('score', 0.0),
                    'crowd_confidence': validation_result.get('confidence', 0.0),
                    'similar_reports': validation_result.get('similar_count', 0),
                    'expert_opinions': validation_result.get('expert_reviews', []),
                    'estimated_severity': validation_result.get('estimated_severity', vulnerability.severity)
                }
            else:
                return {'error': str(response)}
                
        except Exception as e:
            self.logger.error(f"Error getting crowd validation: {e}")
            return {'error': str(e)}

# Example usage
if __name__ == "__main__":
    async def test_bugcrowd_agent():
        """Test Bugcrowd agent functionality"""
        config = {
            'api_token': 'your_api_token'
        }
        
        agent = BugcrowdAgent(config)
        
        # Initialize
        if await agent.initialize():
            print("✅ Bugcrowd agent initialized")
            
            # Get programs
            programs = await agent.get_programs({'offers_rewards': True})
            print(f"Found {len(programs)} programs")
            
            # Get stats
            stats = await agent.get_bugcrowd_stats()
            print(f"Agent stats: {json.dumps(stats, indent=2, default=str)}")
            
            # Cleanup
            await agent.cleanup()
        else:
            print("❌ Failed to initialize Bugcrowd agent")
    
    # Run test
    asyncio.run(test_bugcrowd_agent())
