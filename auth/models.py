#!/usr/bin/env python3
"""
🔐 QuantumSentinel Authentication Models
JWT-based authentication system with SQLAlchemy and user management
"""

import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, create_refresh_token

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and authorization"""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # admin, analyst, user
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # Profile information
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    organization = db.Column(db.String(100))

    # Security preferences
    api_key = db.Column(db.String(64), unique=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)

    # Relationships
    scan_sessions = db.relationship('ScanSession', backref='user', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def __init__(self, username: str, email: str, password: str, role: str = 'user'):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role
        self.generate_api_key()

    def set_password(self, password: str) -> None:
        """Set password with secure hashing"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password: str) -> bool:
        """Check password against stored hash"""
        return check_password_hash(self.password_hash, password)

    def generate_api_key(self) -> str:
        """Generate unique API key for CLI authentication"""
        raw_key = f"{self.username}{self.email}{datetime.utcnow().isoformat()}"
        self.api_key = hashlib.sha256(raw_key.encode()).hexdigest()
        return self.api_key

    def is_locked(self) -> bool:
        """Check if account is locked due to failed login attempts"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def increment_failed_login(self) -> None:
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)

    def reset_failed_login(self) -> None:
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()

    def generate_tokens(self) -> Dict[str, str]:
        """Generate JWT access and refresh tokens"""
        additional_claims = {
            'role': self.role,
            'username': self.username,
            'user_id': self.id
        }

        access_token = create_access_token(
            identity=self.id,
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=2)  # 2-hour access token
        )

        refresh_token = create_refresh_token(
            identity=self.id,
            expires_delta=timedelta(days=30)  # 30-day refresh token
        )

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 7200  # 2 hours in seconds
        }

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission based on role"""
        role_permissions = {
            'admin': ['scan', 'admin', 'manage_users', 'view_all_scans', 'delete_scans'],
            'analyst': ['scan', 'view_scans', 'generate_reports'],
            'user': ['scan', 'view_own_scans']
        }

        user_permissions = role_permissions.get(self.role, [])
        return permission in user_permissions

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary for API responses"""
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'organization': self.organization,
            'two_factor_enabled': self.two_factor_enabled
        }

        if include_sensitive:
            user_dict.update({
                'api_key': self.api_key,
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None
            })

        return user_dict

    def __repr__(self):
        return f'<User {self.username}>'


class ScanSession(db.Model):
    """Scan session model to track user scans and results"""

    __tablename__ = 'scan_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    scan_type = db.Column(db.String(20), nullable=False)  # sast, dast, mobile, binary
    target = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    # Scan configuration and results
    config = db.Column(db.JSON)  # Scan configuration parameters
    results = db.Column(db.JSON)  # Scan results and findings
    findings_count = db.Column(db.Integer, default=0)
    severity_counts = db.Column(db.JSON)  # Count by severity level

    # File paths and reports
    report_path = db.Column(db.String(255))
    evidence_path = db.Column(db.String(255))

    def __init__(self, user_id: int, scan_type: str, target: str, config: Dict[str, Any] = None):
        self.user_id = user_id
        self.scan_type = scan_type
        self.target = target
        self.config = config or {}
        self.session_id = self.generate_session_id()

    def generate_session_id(self) -> str:
        """Generate unique session ID"""
        raw_id = f"{self.user_id}{self.scan_type}{self.target}{datetime.utcnow().isoformat()}"
        return hashlib.sha256(raw_id.encode()).hexdigest()[:16]

    def start_scan(self) -> None:
        """Mark scan as started"""
        self.status = 'running'
        self.started_at = datetime.utcnow()

    def complete_scan(self, results: Dict[str, Any]) -> None:
        """Mark scan as completed with results"""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
        self.results = results

        # Calculate findings statistics
        findings = results.get('findings', [])
        self.findings_count = len(findings)

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        self.severity_counts = severity_counts

    def fail_scan(self, error: str) -> None:
        """Mark scan as failed"""
        self.status = 'failed'
        self.completed_at = datetime.utcnow()
        self.results = {'error': error}

    def get_duration(self) -> Optional[str]:
        """Get scan duration as string"""
        if self.started_at and self.completed_at:
            duration = self.completed_at - self.started_at
            return str(duration)
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan session to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'scan_type': self.scan_type,
            'target': self.target,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.get_duration(),
            'findings_count': self.findings_count,
            'severity_counts': self.severity_counts,
            'config': self.config,
            'report_path': self.report_path
        }


class AuditLog(db.Model):
    """Audit log model for tracking user actions and security events"""

    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # login, logout, scan_start, etc.
    resource = db.Column(db.String(100))  # What was accessed/modified
    ip_address = db.Column(db.String(45))  # Support IPv6
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.JSON)  # Additional context

    def __init__(self, action: str, user_id: int = None, resource: str = None,
                 ip_address: str = None, user_agent: str = None, success: bool = True,
                 details: Dict[str, Any] = None):
        self.action = action
        self.user_id = user_id
        self.resource = resource
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'success': self.success,
            'details': self.details
        }

    @classmethod
    def log_action(cls, action: str, user_id: int = None, resource: str = None,
                   ip_address: str = None, user_agent: str = None, success: bool = True,
                   details: Dict[str, Any] = None) -> 'AuditLog':
        """Create and save an audit log entry"""
        log_entry = cls(
            action=action,
            user_id=user_id,
            resource=resource,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details
        )

        db.session.add(log_entry)
        db.session.commit()

        return log_entry


class APIToken(db.Model):
    """API token model for long-lived API access"""

    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)  # Human-readable token name
    scopes = db.Column(db.JSON)  # List of allowed scopes/permissions
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    user = db.relationship('User', backref='api_tokens')

    def __init__(self, user_id: int, name: str, scopes: list = None, expires_in_days: int = 365):
        self.user_id = user_id
        self.name = name
        self.scopes = scopes or ['scan']
        self.expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        self.token_hash = self.generate_token()

    def generate_token(self) -> str:
        """Generate secure API token"""
        import secrets
        token = secrets.token_urlsafe(32)
        self.token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token  # Return plaintext token (only shown once)

    def is_valid(self) -> bool:
        """Check if token is valid and not expired"""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True

    def use_token(self) -> None:
        """Record token usage"""
        self.last_used = datetime.utcnow()

    def has_scope(self, scope: str) -> bool:
        """Check if token has specific scope"""
        return scope in (self.scopes or [])

    def to_dict(self) -> Dict[str, Any]:
        """Convert API token to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'scopes': self.scopes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }


def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)

    with app.app_context():
        # Create all tables
        db.create_all()

        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@quantumsentinel.local',
                password='quantum_admin_2024',
                role='admin'
            )
            admin_user.first_name = 'System'
            admin_user.last_name = 'Administrator'
            admin_user.organization = 'QuantumSentinel'

            db.session.add(admin_user)
            db.session.commit()

            print(f"✅ Created default admin user - API Key: {admin_user.api_key}")

        # Create sample analyst user
        analyst_user = User.query.filter_by(username='analyst').first()
        if not analyst_user:
            analyst_user = User(
                username='analyst',
                email='analyst@quantumsentinel.local',
                password='quantum_analyst_2024',
                role='analyst'
            )
            analyst_user.first_name = 'Security'
            analyst_user.last_name = 'Analyst'
            analyst_user.organization = 'QuantumSentinel'

            db.session.add(analyst_user)
            db.session.commit()

            print(f"✅ Created default analyst user - API Key: {analyst_user.api_key}")


def create_sample_data():
    """Create sample scan sessions for testing"""
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        # Create sample scan session
        sample_scan = ScanSession(
            user_id=admin_user.id,
            scan_type='sast',
            target='/sample/project',
            config={'deep_analysis': True, 'include_tests': False}
        )

        sample_scan.complete_scan({
            'findings': [
                {'title': 'SQL Injection', 'severity': 'high', 'confidence': 0.9},
                {'title': 'XSS Vulnerability', 'severity': 'medium', 'confidence': 0.8}
            ],
            'summary': {'total_findings': 2, 'high_count': 1, 'medium_count': 1}
        })

        db.session.add(sample_scan)
        db.session.commit()

        print("✅ Created sample scan data")