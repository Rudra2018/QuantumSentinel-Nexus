#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Security Manager
Comprehensive security hardening and validation system for bug bounty platform integration

Security Features:
- Input validation and sanitization
- Rate limiting and throttling
- Secure authentication and authorization
- Encryption for sensitive data
- Audit logging and monitoring
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
import ipaddress
import urllib.parse
from functools import wraps

# Rate limiting imports
from collections import defaultdict, deque

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 10
    session_timeout_minutes: int = 30
    password_min_length: int = 12
    require_mfa: bool = True
    encrypt_sensitive_data: bool = True
    audit_all_requests: bool = True
    allowed_origins: List[str] = None
    
    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = []

@dataclass
class SecurityViolation:
    """Security violation record"""
    violation_type: str
    severity: str  # critical, high, medium, low
    source_ip: str
    user_id: Optional[str]
    timestamp: datetime
    details: Dict[str, Any]
    action_taken: str

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    # Regex patterns for validation
    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$')
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
    FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    # Dangerous patterns to block
    SQL_INJECTION_PATTERNS = [
        r'(\bUNION\b.*\bSELECT\b)',
        r'(\bINSERT\b.*\bINTO\b)',
        r'(\bDELETE\b.*\bFROM\b)',
        r'(\bDROP\b.*\bTABLE\b)',
        r'(\'.*\bOR\b.*\')',
        r'(\".*\bOR\b.*\")',
    ]
    
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>'
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./\.\./',
        r'\\\.\.\\\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e\\',
        r'\.\.%2f',
        r'\.\.%5c'
    ]
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Length check
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        
        # Check for dangerous patterns
        value_lower = value.lower()
        
        # SQL injection detection
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                raise ValueError("Potential SQL injection detected")
        
        # XSS detection
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                raise ValueError("Potential XSS attack detected")
        
        # Path traversal detection
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                raise ValueError("Path traversal attempt detected")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
        
        return sanitized.strip()
    
    @staticmethod
    def validate_target(target: str) -> bool:
        """Validate security testing target"""
        if not target:
            return False
        
        target = InputValidator.sanitize_string(target, 253)  # Max domain length
        
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(target)
            # Block private/reserved IP ranges for security
            ip = ipaddress.ip_address(target)
            if ip.is_private or ip.is_reserved or ip.is_loopback:
                return False
            return True
        except ValueError:
            pass
        
        # Check if it's a valid domain
        if InputValidator.DOMAIN_PATTERN.match(target):
            # Block localhost and internal domains
            blocked_domains = ['localhost', '127.0.0.1', '0.0.0.0', 'internal', 'local']
            if any(blocked in target.lower() for blocked in blocked_domains):
                return False
            return True
        
        return False
    
    @staticmethod
    def validate_cve_id(cve_id: str) -> bool:
        """Validate CVE identifier format"""
        if not cve_id:
            return False
        
        cve_id = InputValidator.sanitize_string(cve_id, 20)
        return bool(InputValidator.CVE_PATTERN.match(cve_id))
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        """Validate filename for security"""
        if not filename:
            return False
        
        filename = InputValidator.sanitize_string(filename, 255)
        
        # Check for valid filename pattern
        if not InputValidator.FILENAME_PATTERN.match(filename):
            return False
        
        # Block dangerous file extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.py', '.php', '.jsp']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            return False
        
        return True
    
    @staticmethod
    def validate_json_data(data: Any, max_depth: int = 10) -> bool:
        """Validate JSON data structure"""
        def check_depth(obj, current_depth=0):
            if current_depth > max_depth:
                return False
            
            if isinstance(obj, dict):
                if len(obj) > 100:  # Limit dict size
                    return False
                for key, value in obj.items():
                    if not isinstance(key, str) or len(key) > 100:
                        return False
                    if not check_depth(value, current_depth + 1):
                        return False
            elif isinstance(obj, list):
                if len(obj) > 1000:  # Limit list size
                    return False
                for item in obj:
                    if not check_depth(item, current_depth + 1):
                        return False
            elif isinstance(obj, str):
                if len(obj) > 10000:  # Limit string length
                    return False
                try:
                    InputValidator.sanitize_string(obj)
                except ValueError:
                    return False
            
            return True
        
        return check_depth(data)

class RateLimiter:
    """Advanced rate limiting with multiple algorithms"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.requests_per_minute = defaultdict(lambda: deque())
        self.requests_per_hour = defaultdict(lambda: deque())
        self.concurrent_requests = defaultdict(int)
        self.blocked_ips = {}
        
    def is_rate_limited(self, client_id: str) -> Tuple[bool, str]:
        """Check if client is rate limited"""
        now = time.time()
        
        # Check if IP is temporarily blocked
        if client_id in self.blocked_ips:
            if now < self.blocked_ips[client_id]:
                return True, "IP temporarily blocked due to rate limit violations"
            else:
                del self.blocked_ips[client_id]
        
        # Clean old requests
        self._clean_old_requests(client_id, now)
        
        # Check per-minute limit
        minute_requests = len(self.requests_per_minute[client_id])
        if minute_requests >= self.config.max_requests_per_minute:
            self._block_ip(client_id, 300)  # Block for 5 minutes
            return True, f"Rate limit exceeded: {minute_requests}/{self.config.max_requests_per_minute} per minute"
        
        # Check per-hour limit
        hour_requests = len(self.requests_per_hour[client_id])
        if hour_requests >= self.config.max_requests_per_hour:
            self._block_ip(client_id, 3600)  # Block for 1 hour
            return True, f"Rate limit exceeded: {hour_requests}/{self.config.max_requests_per_hour} per hour"
        
        # Check concurrent requests
        if self.concurrent_requests[client_id] >= self.config.max_concurrent_requests:
            return True, f"Too many concurrent requests: {self.concurrent_requests[client_id]}/{self.config.max_concurrent_requests}"
        
        return False, ""
    
    def record_request(self, client_id: str):
        """Record a new request"""
        now = time.time()
        self.requests_per_minute[client_id].append(now)
        self.requests_per_hour[client_id].append(now)
        self.concurrent_requests[client_id] += 1
    
    def release_request(self, client_id: str):
        """Release a completed request"""
        if self.concurrent_requests[client_id] > 0:
            self.concurrent_requests[client_id] -= 1
    
    def _clean_old_requests(self, client_id: str, now: float):
        """Clean old request records"""
        # Clean minute requests (older than 60 seconds)
        minute_queue = self.requests_per_minute[client_id]
        while minute_queue and now - minute_queue[0] > 60:
            minute_queue.popleft()
        
        # Clean hour requests (older than 3600 seconds)
        hour_queue = self.requests_per_hour[client_id]
        while hour_queue and now - hour_queue[0] > 3600:
            hour_queue.popleft()
    
    def _block_ip(self, client_id: str, duration: int):
        """Temporarily block an IP address"""
        self.blocked_ips[client_id] = time.time() + duration

class EncryptionManager:
    """Handle encryption/decryption of sensitive data"""
    
    def __init__(self, master_key: Optional[str] = None):
        if master_key:
            key = master_key.encode()
        else:
            key = secrets.token_bytes(32)
        
        # Derive encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'quantumsentinel',  # In production, use random salt
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key))
        self.cipher = Fernet(derived_key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return data
        
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return encrypted_data
        
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception:
            raise ValueError("Failed to decrypt data")
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if not salt:
            salt = secrets.token_hex(16)
        
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return base64.urlsafe_b64encode(pwd_hash).decode(), salt
    
    def verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash"""
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(base64.urlsafe_b64decode(hashed.encode()), pwd_hash)

class SecurityManager:
    """Main security manager for QuantumSentinel-Nexus"""
    
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.validator = InputValidator()
        self.rate_limiter = RateLimiter(self.config)
        self.encryption = EncryptionManager()
        self.logger = logging.getLogger('QuantumSentinel.Security')
        
        # Security event tracking
        self.violations = []
        self.session_store = {}
        
        # Initialize audit logging
        self._setup_audit_logging()
    
    def _setup_audit_logging(self):
        """Setup security audit logging"""
        audit_logger = logging.getLogger('QuantumSentinel.Security.Audit')
        audit_logger.setLevel(logging.INFO)
        
        # Create audit log handler (in production, use secure remote logging)
        handler = logging.FileHandler('security_audit.log')
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
        
        self.audit_logger = audit_logger
    
    def validate_request(self, request_data: Dict[str, Any], client_ip: str) -> Tuple[bool, str]:
        """Comprehensive request validation"""
        try:
            # Rate limiting check
            is_limited, limit_msg = self.rate_limiter.is_rate_limited(client_ip)
            if is_limited:
                self._log_security_violation(
                    'rate_limit_exceeded',
                    'medium',
                    client_ip,
                    None,
                    {'message': limit_msg}
                )
                return False, limit_msg
            
            # Input validation
            if not self.validator.validate_json_data(request_data):
                self._log_security_violation(
                    'invalid_input_data',
                    'high',
                    client_ip,
                    None,
                    {'data_keys': list(request_data.keys()) if isinstance(request_data, dict) else 'non_dict'}
                )
                return False, "Invalid request data format"
            
            # Validate specific fields
            if 'targets' in request_data:
                targets = request_data['targets']
                if not isinstance(targets, list) or not targets:
                    return False, "Targets must be a non-empty list"
                
                for target in targets:
                    if not self.validator.validate_target(str(target)):
                        self._log_security_violation(
                            'invalid_target',
                            'high',
                            client_ip,
                            None,
                            {'target': target}
                        )
                        return False, f"Invalid or unauthorized target: {target}"
            
            # Record successful request
            self.rate_limiter.record_request(client_ip)
            
            if self.config.audit_all_requests:
                self.audit_logger.info(f"VALID_REQUEST - IP: {client_ip} - Data: {json.dumps(request_data, default=str)[:200]}...")
            
            return True, "Request validated successfully"
            
        except Exception as e:
            self.logger.error(f"Request validation error: {e}")
            self._log_security_violation(
                'validation_error',
                'high',
                client_ip,
                None,
                {'error': str(e)}
            )
            return False, "Request validation failed"
    
    def _log_security_violation(self, violation_type: str, severity: str, 
                              source_ip: str, user_id: Optional[str], 
                              details: Dict[str, Any]):
        """Log security violation"""
        violation = SecurityViolation(
            violation_type=violation_type,
            severity=severity,
            source_ip=source_ip,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            details=details,
            action_taken="blocked" if severity in ['critical', 'high'] else "logged"
        )
        
        self.violations.append(violation)
        
        # Log to audit system
        self.audit_logger.warning(
            f"SECURITY_VIOLATION - Type: {violation_type} - Severity: {severity} - "
            f"IP: {source_ip} - User: {user_id} - Details: {json.dumps(details, default=str)}"
        )
        
        # Alert if critical
        if severity == 'critical':
            self.logger.critical(f"CRITICAL SECURITY VIOLATION: {violation_type} from {source_ip}")
    
    def create_session(self, user_id: str, client_ip: str) -> str:
        """Create secure session"""
        session_id = secrets.token_urlsafe(32)
        session_data = {
            'user_id': user_id,
            'client_ip': client_ip,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=self.config.session_timeout_minutes),
            'last_activity': datetime.utcnow()
        }
        
        self.session_store[session_id] = session_data
        
        self.audit_logger.info(f"SESSION_CREATED - User: {user_id} - IP: {client_ip} - Session: {session_id}")
        
        return session_id
    
    def validate_session(self, session_id: str, client_ip: str) -> Tuple[bool, Optional[str]]:
        """Validate session"""
        if not session_id or session_id not in self.session_store:
            return False, None
        
        session = self.session_store[session_id]
        now = datetime.utcnow()
        
        # Check expiration
        if now > session['expires_at']:
            del self.session_store[session_id]
            return False, None
        
        # Check IP consistency (optional security measure)
        if session['client_ip'] != client_ip:
            self._log_security_violation(
                'session_ip_mismatch',
                'high',
                client_ip,
                session['user_id'],
                {'session_ip': session['client_ip'], 'request_ip': client_ip}
            )
            return False, None
        
        # Update last activity
        session['last_activity'] = now
        
        return True, session['user_id']
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        if session_id in self.session_store:
            user_id = self.session_store[session_id]['user_id']
            del self.session_store[session_id]
            self.audit_logger.info(f"SESSION_INVALIDATED - User: {user_id} - Session: {session_id}")
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate security report"""
        return {
            'total_violations': len(self.violations),
            'violations_by_severity': {
                'critical': len([v for v in self.violations if v.severity == 'critical']),
                'high': len([v for v in self.violations if v.severity == 'high']),
                'medium': len([v for v in self.violations if v.severity == 'medium']),
                'low': len([v for v in self.violations if v.severity == 'low'])
            },
            'violations_by_type': {},
            'active_sessions': len(self.session_store),
            'blocked_ips': len(self.rate_limiter.blocked_ips),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.utcnow()
        expired_sessions = [
            session_id for session_id, session in self.session_store.items()
            if now > session['expires_at']
        ]
        
        for session_id in expired_sessions:
            del self.session_store[session_id]
        
        self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

# Decorator for securing endpoints
def require_security_validation(security_manager: SecurityManager):
    """Decorator to add security validation to endpoints"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request data and client IP from function arguments
            # This would need to be adapted based on your framework (FastAPI, Flask, etc.)
            request_data = kwargs.get('request_data', {})
            client_ip = kwargs.get('client_ip', '127.0.0.1')
            
            # Validate request
            is_valid, message = security_manager.validate_request(request_data, client_ip)
            if not is_valid:
                raise SecurityError(message)
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                security_manager.rate_limiter.release_request(client_ip)
        
        return wrapper
    return decorator

class SecurityError(Exception):
    """Security-related exception"""
    pass

# Example usage and testing
if __name__ == "__main__":
    async def test_security_manager():
        """Test security manager functionality"""
        config = SecurityConfig(
            max_requests_per_minute=5,
            max_requests_per_hour=100,
            max_concurrent_requests=3
        )
        
        security_manager = SecurityManager(config)
        
        # Test input validation
        test_requests = [
            {"targets": ["example.com"], "assessment_type": "vulnerability_scan"},
            {"targets": ["127.0.0.1"], "assessment_type": "scan"},  # Should fail
            {"targets": ["'; DROP TABLE users; --"], "assessment_type": "scan"},  # Should fail
            {"targets": ["<script>alert('xss')</script>"], "assessment_type": "scan"},  # Should fail
        ]
        
        for i, request in enumerate(test_requests):
            is_valid, message = security_manager.validate_request(request, f"192.168.1.{i+1}")
            print(f"Request {i+1}: {'VALID' if is_valid else 'INVALID'} - {message}")
        
        # Test rate limiting
        client_ip = "192.168.1.100"
        for i in range(7):  # Exceed rate limit
            is_valid, message = security_manager.validate_request(
                {"targets": ["example.com"], "assessment_type": "scan"}, 
                client_ip
            )
            print(f"Rate limit test {i+1}: {'VALID' if is_valid else 'INVALID'} - {message}")
        
        # Generate security report
        report = security_manager.get_security_report()
        print(f"\nSecurity Report: {json.dumps(report, indent=2)}")
    
    # Run test
    asyncio.run(test_security_manager())
