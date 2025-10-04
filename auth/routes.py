#!/usr/bin/env python3
"""
🔐 QuantumSentinel Authentication Routes
JWT-based authentication endpoints for Web UI and CLI access
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, create_access_token,
    create_refresh_token, get_jwt, verify_jwt_in_request
)
from werkzeug.exceptions import BadRequest
import hashlib

from .models import db, User, ScanSession, AuditLog, APIToken
from .validators import validate_registration, validate_login, validate_password_strength

logger = logging.getLogger("QuantumSentinel.Auth")

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

def get_client_ip():
    """Get client IP address from request"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

def get_user_agent():
    """Get user agent from request"""
    return request.headers.get('User-Agent', 'unknown')

def log_auth_event(action: str, user_id: int = None, success: bool = True, details: Dict[str, Any] = None):
    """Log authentication event to audit log"""
    AuditLog.log_action(
        action=action,
        user_id=user_id,
        ip_address=get_client_ip(),
        user_agent=get_user_agent(),
        success=success,
        details=details or {}
    )


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register new user account"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate registration data
        validation_result = validate_registration(data)
        if not validation_result['valid']:
            log_auth_event('register_attempt', success=False, details={'errors': validation_result['errors']})
            return jsonify({'error': 'Validation failed', 'details': validation_result['errors']}), 400

        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        password = data['password']

        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            log_auth_event('register_attempt', success=False, details={'reason': 'user_exists'})
            return jsonify({'error': 'User with this username or email already exists'}), 409

        # Validate password strength
        password_validation = validate_password_strength(password)
        if not password_validation['valid']:
            log_auth_event('register_attempt', success=False, details={'reason': 'weak_password'})
            return jsonify({'error': 'Password too weak', 'details': password_validation['issues']}), 400

        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=password,
            role=data.get('role', 'user')  # Default to 'user' role
        )

        # Set optional profile information
        if 'first_name' in data:
            new_user.first_name = data['first_name'].strip()
        if 'last_name' in data:
            new_user.last_name = data['last_name'].strip()
        if 'organization' in data:
            new_user.organization = data['organization'].strip()

        db.session.add(new_user)
        db.session.commit()

        # Generate tokens
        tokens = new_user.generate_tokens()

        log_auth_event('register_success', user_id=new_user.id, details={'username': username})

        return jsonify({
            'message': 'User registered successfully',
            'user': new_user.to_dict(),
            'tokens': tokens,
            'api_key': new_user.api_key
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {e}")
        log_auth_event('register_error', success=False, details={'error': str(e)})
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """User login with username/email and password"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate login data
        validation_result = validate_login(data)
        if not validation_result['valid']:
            log_auth_event('login_attempt', success=False, details={'errors': validation_result['errors']})
            return jsonify({'error': 'Validation failed', 'details': validation_result['errors']}), 400

        identifier = data['identifier'].strip().lower()  # username or email
        password = data['password']

        # Find user by username or email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if not user:
            log_auth_event('login_attempt', success=False, details={'identifier': identifier, 'reason': 'user_not_found'})
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if account is locked
        if user.is_locked():
            log_auth_event('login_attempt', user_id=user.id, success=False, details={'reason': 'account_locked'})
            return jsonify({'error': 'Account is temporarily locked due to too many failed attempts'}), 423

        # Check if account is active
        if not user.is_active:
            log_auth_event('login_attempt', user_id=user.id, success=False, details={'reason': 'account_inactive'})
            return jsonify({'error': 'Account is deactivated'}), 401

        # Verify password
        if not user.check_password(password):
            user.increment_failed_login()
            db.session.commit()

            log_auth_event('login_attempt', user_id=user.id, success=False, details={'reason': 'invalid_password'})
            return jsonify({'error': 'Invalid credentials'}), 401

        # Successful login
        user.reset_failed_login()
        db.session.commit()

        # Generate tokens
        tokens = user.generate_tokens()

        log_auth_event('login_success', user_id=user.id, details={'username': user.username})

        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'tokens': tokens
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}")
        log_auth_event('login_error', success=False, details={'error': str(e)})
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or not user.is_active:
            log_auth_event('token_refresh', user_id=user_id, success=False, details={'reason': 'invalid_user'})
            return jsonify({'error': 'Invalid user'}), 401

        # Generate new access token
        tokens = user.generate_tokens()

        log_auth_event('token_refresh', user_id=user.id, details={'username': user.username})

        return jsonify({
            'message': 'Token refreshed successfully',
            'tokens': tokens
        }), 200

    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout (client-side token removal)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if user:
            log_auth_event('logout', user_id=user.id, details={'username': user.username})

        return jsonify({'message': 'Logout successful'}), 200

    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'user': user.to_dict(),
            'recent_scans': [
                scan.to_dict() for scan in user.scan_sessions.order_by(
                    ScanSession.created_at.desc()
                ).limit(5)
            ]
        }), 200

    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        updatable_fields = ['first_name', 'last_name', 'organization']
        updated_fields = []

        for field in updatable_fields:
            if field in data:
                setattr(user, field, data[field].strip() if data[field] else None)
                updated_fields.append(field)

        db.session.commit()

        log_auth_event('profile_update', user_id=user.id, details={'updated_fields': updated_fields})

        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password are required'}), 400

        # Verify current password
        if not user.check_password(current_password):
            log_auth_event('password_change', user_id=user.id, success=False, details={'reason': 'invalid_current_password'})
            return jsonify({'error': 'Current password is incorrect'}), 401

        # Validate new password strength
        password_validation = validate_password_strength(new_password)
        if not password_validation['valid']:
            return jsonify({'error': 'New password too weak', 'details': password_validation['issues']}), 400

        # Update password
        user.set_password(new_password)
        db.session.commit()

        log_auth_event('password_change', user_id=user.id, details={'username': user.username})

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/api-tokens', methods=['GET'])
@jwt_required()
def list_api_tokens():
    """List user's API tokens"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        tokens = APIToken.query.filter_by(user_id=user_id).all()

        return jsonify({
            'tokens': [token.to_dict() for token in tokens]
        }), 200

    except Exception as e:
        logger.error(f"API tokens list error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/api-tokens', methods=['POST'])
@jwt_required()
def create_api_token():
    """Create new API token"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        name = data.get('name', '').strip()
        scopes = data.get('scopes', ['scan'])
        expires_in_days = data.get('expires_in_days', 365)

        if not name:
            return jsonify({'error': 'Token name is required'}), 400

        # Create new API token
        api_token = APIToken(
            user_id=user_id,
            name=name,
            scopes=scopes,
            expires_in_days=expires_in_days
        )

        # Generate the actual token (only shown once)
        token_value = api_token.generate_token()

        db.session.add(api_token)
        db.session.commit()

        log_auth_event('api_token_created', user_id=user.id, details={'token_name': name})

        return jsonify({
            'message': 'API token created successfully',
            'token': token_value,  # Only shown once!
            'token_info': api_token.to_dict()
        }), 201

    except Exception as e:
        logger.error(f"API token creation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/api-tokens/<int:token_id>', methods=['DELETE'])
@jwt_required()
def delete_api_token(token_id):
    """Delete API token"""
    try:
        user_id = get_jwt_identity()
        api_token = APIToken.query.filter_by(id=token_id, user_id=user_id).first()

        if not api_token:
            return jsonify({'error': 'Token not found'}), 404

        token_name = api_token.name
        db.session.delete(api_token)
        db.session.commit()

        log_auth_event('api_token_deleted', user_id=user_id, details={'token_name': token_name})

        return jsonify({'message': 'API token deleted successfully'}), 200

    except Exception as e:
        logger.error(f"API token deletion error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# CLI Authentication endpoint
@auth_bp.route('/cli-auth', methods=['POST'])
def cli_authenticate():
    """Authenticate CLI using API key"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        api_key = data.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key is required'}), 400

        # Find user by API key
        user = User.query.filter_by(api_key=api_key).first()

        if not user or not user.is_active:
            log_auth_event('cli_auth_attempt', success=False, details={'reason': 'invalid_api_key'})
            return jsonify({'error': 'Invalid API key'}), 401

        # Generate tokens for CLI
        tokens = user.generate_tokens()

        log_auth_event('cli_auth_success', user_id=user.id, details={'username': user.username})

        return jsonify({
            'message': 'CLI authentication successful',
            'user': user.to_dict(),
            'tokens': tokens
        }), 200

    except Exception as e:
        logger.error(f"CLI authentication error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Admin endpoints
@auth_bp.route('/admin/users', methods=['GET'])
@jwt_required()
def list_users():
    """List all users (admin only)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or not user.has_permission('manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403

        users = User.query.all()

        return jsonify({
            'users': [u.to_dict() for u in users]
        }), 200

    except Exception as e:
        logger.error(f"List users error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/admin/users/<int:target_user_id>', methods=['PUT'])
@jwt_required()
def update_user(target_user_id):
    """Update user (admin only)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or not user.has_permission('manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403

        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        updatable_fields = ['role', 'is_active', 'first_name', 'last_name', 'organization']
        updated_fields = []

        for field in updatable_fields:
            if field in data:
                setattr(target_user, field, data[field])
                updated_fields.append(field)

        db.session.commit()

        log_auth_event('user_update', user_id=user.id, details={
            'target_user': target_user.username,
            'updated_fields': updated_fields
        })

        return jsonify({
            'message': 'User updated successfully',
            'user': target_user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"User update error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """Verify JWT token validity"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or not user.is_active:
            return jsonify({'error': 'Invalid token'}), 401

        jwt_data = get_jwt()

        return jsonify({
            'valid': True,
            'user': user.to_dict(),
            'token_info': {
                'exp': jwt_data.get('exp'),
                'iat': jwt_data.get('iat'),
                'role': jwt_data.get('role')
            }
        }), 200

    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Authentication decorator for CLI
def require_auth(f):
    """Decorator to require authentication for CLI operations"""
    def decorated_function(*args, **kwargs):
        try:
            # Check for API key in headers
            api_key = request.headers.get('X-API-Key')
            if api_key:
                user = User.query.filter_by(api_key=api_key).first()
                if user and user.is_active:
                    request.current_user = user
                    return f(*args, **kwargs)

            # Check for JWT token
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if user and user.is_active:
                request.current_user = user
                return f(*args, **kwargs)

            return jsonify({'error': 'Authentication required'}), 401

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401

    return decorated_function


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user') or not request.current_user:
                return jsonify({'error': 'Authentication required'}), 401

            if not request.current_user.has_permission(permission):
                return jsonify({'error': 'Insufficient permissions'}), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator