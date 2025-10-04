#!/usr/bin/env python3
"""
📝 QuantumSentinel Security Logging System
Advanced structured logging with security audit trails
"""

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class SecurityLogger:
    """Enhanced security logger with audit trail capabilities"""

    def __init__(self, component_name: str, log_level: str = "INFO"):
        self.component_name = component_name
        self.logger = logging.getLogger(f"QuantumSentinel.{component_name}")

        # Set log level
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger.setLevel(numeric_level)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Setup logging handlers"""

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # File handler
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / f"{self.component_name}.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)

        # Security audit handler
        audit_handler = logging.handlers.RotatingFileHandler(
            log_dir / "security_audit.log",
            maxBytes=50*1024*1024,  # 50MB
            backupCount=10
        )
        audit_handler.setLevel(logging.INFO)

        # Formatters
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )

        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(name)s - %(message)s'
        )

        # Set formatters
        console_handler.setFormatter(console_formatter)
        file_handler.setFormatter(file_formatter)
        audit_handler.setFormatter(audit_formatter)

        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        # Store audit handler for security events
        self.audit_handler = audit_handler
        self.audit_logger = logging.getLogger(f"QuantumSentinel.Audit.{self.component_name}")
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, **kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, **kwargs)

    def audit(self, event_type: str, details: Dict[str, Any]):
        """Log security audit event"""

        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'component': self.component_name,
            'event_type': event_type,
            'details': details,
            'session_id': details.get('session_id', 'unknown')
        }

        self.audit_logger.info(json.dumps(audit_entry))

# Global logger instances
def get_logger(component_name: str, log_level: str = "INFO") -> SecurityLogger:
    """Get logger instance for component"""
    return SecurityLogger(component_name, log_level)