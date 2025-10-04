#!/usr/bin/env python3
"""
🔐 QuantumSentinel Authentication Package
JWT-based authentication system for Web UI and CLI access
"""

from .models import db, User, ScanSession, AuditLog, APIToken, init_db, create_sample_data
from .routes import auth_bp, require_auth, require_permission
from .validators import (
    validate_registration, validate_login, validate_password_strength,
    validate_scan_config, validate_api_key_format, sanitize_input
)

__all__ = [
    'db', 'User', 'ScanSession', 'AuditLog', 'APIToken',
    'init_db', 'create_sample_data',
    'auth_bp', 'require_auth', 'require_permission',
    'validate_registration', 'validate_login', 'validate_password_strength',
    'validate_scan_config', 'validate_api_key_format', 'sanitize_input'
]