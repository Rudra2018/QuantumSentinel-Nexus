#!/usr/bin/env python3
"""
🔐 QuantumSentinel Authentication Validators
Input validation and security checks for authentication system
"""

import re
from typing import Dict, Any, List


def validate_email(email: str) -> bool:
    """Validate email format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def validate_username(username: str) -> Dict[str, Any]:
    """Validate username format and requirements"""
    issues = []

    if not username:
        issues.append("Username is required")
    else:
        if len(username) < 3:
            issues.append("Username must be at least 3 characters long")
        if len(username) > 30:
            issues.append("Username must be less than 30 characters")
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            issues.append("Username can only contain letters, numbers, dots, hyphens, and underscores")
        if username.startswith('.') or username.endswith('.'):
            issues.append("Username cannot start or end with a dot")
        if '..' in username:
            issues.append("Username cannot contain consecutive dots")

    return {
        'valid': len(issues) == 0,
        'issues': issues
    }


def validate_password_strength(password: str) -> Dict[str, Any]:
    """Validate password strength and complexity"""
    issues = []
    score = 0

    if not password:
        return {'valid': False, 'issues': ['Password is required'], 'score': 0}

    # Length requirements
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    else:
        score += 1

    if len(password) >= 12:
        score += 1

    # Character type requirements
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    if not has_upper:
        issues.append("Password must contain at least one uppercase letter")
    else:
        score += 1

    if not has_lower:
        issues.append("Password must contain at least one lowercase letter")
    else:
        score += 1

    if not has_digit:
        issues.append("Password must contain at least one number")
    else:
        score += 1

    if not has_special:
        issues.append("Password must contain at least one special character")
    else:
        score += 1

    # Common password checks
    common_passwords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey'
    ]

    if password.lower() in common_passwords:
        issues.append("Password is too common, please choose a different one")
        score = max(0, score - 2)

    # Sequential characters check
    if re.search(r'(.)\1{2,}', password):  # 3+ repeated characters
        issues.append("Password should not contain repeated characters")
        score = max(0, score - 1)

    # Keyboard patterns
    keyboard_patterns = ['qwerty', 'asdf', '1234', 'abcd']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            issues.append("Password should not contain keyboard patterns")
            score = max(0, score - 1)
            break

    # Calculate strength
    if score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Medium"
    elif score >= 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'score': score,
        'strength': strength
    }


def validate_registration(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate user registration data"""
    errors = []

    # Required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f"{field.title()} is required")

    if errors:
        return {'valid': False, 'errors': errors}

    # Validate username
    username_validation = validate_username(data['username'])
    if not username_validation['valid']:
        errors.extend(username_validation['issues'])

    # Validate email
    if not validate_email(data['email']):
        errors.append("Invalid email format")

    # Validate password
    password_validation = validate_password_strength(data['password'])
    if not password_validation['valid']:
        errors.extend(password_validation['issues'])

    # Validate role if provided
    if 'role' in data:
        valid_roles = ['user', 'analyst', 'admin']
        if data['role'] not in valid_roles:
            errors.append(f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    # Validate optional fields
    optional_fields = ['first_name', 'last_name', 'organization']
    for field in optional_fields:
        if field in data and data[field]:
            if len(data[field]) > 100:
                errors.append(f"{field.replace('_', ' ').title()} must be less than 100 characters")
            if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', data[field]):
                errors.append(f"{field.replace('_', ' ').title()} contains invalid characters")

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_login(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate user login data"""
    errors = []

    # Required fields
    if 'identifier' not in data or not data['identifier']:
        errors.append("Username or email is required")

    if 'password' not in data or not data['password']:
        errors.append("Password is required")

    # Validate identifier format (can be username or email)
    if 'identifier' in data and data['identifier']:
        identifier = data['identifier'].strip()

        # Check if it's an email format
        if '@' in identifier:
            if not validate_email(identifier):
                errors.append("Invalid email format")
        else:
            # Validate as username
            username_validation = validate_username(identifier)
            if not username_validation['valid']:
                errors.append("Invalid username format")

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_scan_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate scan configuration data"""
    errors = []

    # Required fields
    required_fields = ['scan_type', 'target']
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f"{field.replace('_', ' ').title()} is required")

    if errors:
        return {'valid': False, 'errors': errors}

    # Validate scan type
    valid_scan_types = ['sast', 'dast', 'mobile', 'binary', 'ai_analysis']
    if data['scan_type'] not in valid_scan_types:
        errors.append(f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}")

    # Validate target based on scan type
    target = data['target'].strip()
    scan_type = data['scan_type']

    if scan_type == 'dast':
        # Validate URL format
        url_pattern = r'^https?://.+$'
        if not re.match(url_pattern, target):
            errors.append("DAST target must be a valid HTTP/HTTPS URL")
    elif scan_type in ['sast', 'binary']:
        # Validate file/directory path
        if not target or len(target) < 1:
            errors.append(f"{scan_type.upper()} target must be a valid file or directory path")
    elif scan_type == 'mobile':
        # Validate mobile app file
        if not target.endswith(('.apk', '.ipa')):
            errors.append("Mobile target must be an APK or IPA file")

    # Validate optional configuration
    if 'config' in data and isinstance(data['config'], dict):
        config = data['config']

        # Validate timeout
        if 'timeout' in config:
            try:
                timeout = int(config['timeout'])
                if timeout < 10 or timeout > 3600:  # 10 seconds to 1 hour
                    errors.append("Timeout must be between 10 and 3600 seconds")
            except (ValueError, TypeError):
                errors.append("Timeout must be a valid number")

        # Validate depth for DAST scans
        if scan_type == 'dast' and 'max_depth' in config:
            try:
                depth = int(config['max_depth'])
                if depth < 1 or depth > 10:
                    errors.append("DAST max depth must be between 1 and 10")
            except (ValueError, TypeError):
                errors.append("Max depth must be a valid number")

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_api_key_format(api_key: str) -> bool:
    """Validate API key format"""
    if not api_key:
        return False

    # API keys should be 64 character hex strings
    return bool(re.match(r'^[a-f0-9]{64}$', api_key))


def sanitize_input(input_string: str, max_length: int = 255) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not input_string:
        return ""

    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>&"\']', '', input_string)

    # Limit length
    sanitized = sanitized[:max_length]

    # Remove leading/trailing whitespace
    sanitized = sanitized.strip()

    return sanitized


def validate_file_upload(file_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate file upload for security scanning"""
    errors = []

    if 'filename' not in file_data or not file_data['filename']:
        errors.append("Filename is required")
        return {'valid': False, 'errors': errors}

    filename = file_data['filename']

    # Check file extension
    allowed_extensions = {
        'sast': ['.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs', '.zip', '.tar.gz'],
        'mobile': ['.apk', '.ipa'],
        'binary': ['.exe', '.dll', '.so', '.dylib', '.bin'],
        'dast': []  # DAST doesn't typically use file uploads
    }

    scan_type = file_data.get('scan_type', '')
    if scan_type in allowed_extensions:
        valid_extensions = allowed_extensions[scan_type]
        if valid_extensions and not any(filename.lower().endswith(ext) for ext in valid_extensions):
            errors.append(f"Invalid file type for {scan_type.upper()} scan. Allowed: {', '.join(valid_extensions)}")

    # Check file size (if provided)
    if 'size' in file_data:
        try:
            size_mb = int(file_data['size']) / (1024 * 1024)  # Convert to MB
            max_sizes = {
                'sast': 100,   # 100MB for source code
                'mobile': 200, # 200MB for mobile apps
                'binary': 50   # 50MB for binaries
            }

            max_size = max_sizes.get(scan_type, 100)
            if size_mb > max_size:
                errors.append(f"File too large. Maximum size for {scan_type.upper()}: {max_size}MB")
        except (ValueError, TypeError):
            errors.append("Invalid file size")

    # Security checks
    dangerous_patterns = [
        r'\.\./', # Path traversal
        r'<script', # XSS
        r'javascript:', # JavaScript injection
        r'data:', # Data URI
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, filename, re.IGNORECASE):
            errors.append("Filename contains potentially dangerous characters")
            break

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_report_request(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate report generation request"""
    errors = []

    # Required fields
    if 'session_id' not in data or not data['session_id']:
        errors.append("Session ID is required")

    # Validate format
    if 'format' in data:
        valid_formats = ['json', 'html', 'pdf']
        if data['format'] not in valid_formats:
            errors.append(f"Invalid format. Must be one of: {', '.join(valid_formats)}")

    # Validate include_raw_data flag
    if 'include_raw_data' in data and not isinstance(data['include_raw_data'], bool):
        errors.append("include_raw_data must be a boolean value")

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_webhook_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate webhook configuration"""
    errors = []

    # Required fields
    if 'url' not in data or not data['url']:
        errors.append("Webhook URL is required")
    else:
        # Validate URL format
        if not re.match(r'^https?://.+$', data['url']):
            errors.append("Webhook URL must be a valid HTTP/HTTPS URL")

    # Validate events
    if 'events' in data:
        if not isinstance(data['events'], list):
            errors.append("Events must be a list")
        else:
            valid_events = ['scan_completed', 'scan_failed', 'scan_started']
            for event in data['events']:
                if event not in valid_events:
                    errors.append(f"Invalid event: {event}. Valid events: {', '.join(valid_events)}")

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }