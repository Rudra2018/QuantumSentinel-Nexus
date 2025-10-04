#!/usr/bin/env python3
"""
⚙️ QuantumSentinel Configuration Management
Centralized configuration with environment variable support
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

@dataclass
class DatabaseConfig:
    """Database configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "quantumsentinel"
    username: str = "quantum"
    password: str = "quantum123"

    @classmethod
    def from_env(cls):
        return cls(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "quantumsentinel"),
            username=os.getenv("DB_USER", "quantum"),
            password=os.getenv("DB_PASSWORD", "quantum123")
        )

@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str = "quantum-sentinel-secret-key-change-me"
    jwt_expiration: int = 3600
    max_upload_size: int = 100 * 1024 * 1024  # 100MB
    allowed_extensions: List[str] = field(default_factory=lambda: ['.apk', '.ipa', '.exe', '.dll', '.so'])

    @classmethod
    def from_env(cls):
        return cls(
            secret_key=os.getenv("SECRET_KEY", "quantum-sentinel-secret-key-change-me"),
            jwt_expiration=int(os.getenv("JWT_EXPIRATION", "3600")),
            max_upload_size=int(os.getenv("MAX_UPLOAD_SIZE", str(100 * 1024 * 1024))),
            allowed_extensions=os.getenv("ALLOWED_EXTENSIONS", ".apk,.ipa,.exe,.dll,.so").split(",")
        )

@dataclass
class AIConfig:
    """AI/ML configuration"""
    model_path: str = "models/"
    use_transformers: bool = True
    use_traditional_ml: bool = True
    confidence_threshold: float = 0.7

    @classmethod
    def from_env(cls):
        return cls(
            model_path=os.getenv("AI_MODEL_PATH", "models/"),
            use_transformers=os.getenv("USE_TRANSFORMERS", "true").lower() == "true",
            use_traditional_ml=os.getenv("USE_TRADITIONAL_ML", "true").lower() == "true",
            confidence_threshold=float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.7"))
        )

@dataclass
class WorkflowConfig:
    """Workflow configuration"""
    max_parallel_tasks: int = 10
    task_timeout: int = 3600
    workflow_storage: str = "workflows/"

    @classmethod
    def from_env(cls):
        return cls(
            max_parallel_tasks=int(os.getenv("MAX_PARALLEL_TASKS", "10")),
            task_timeout=int(os.getenv("TASK_TIMEOUT", "3600")),
            workflow_storage=os.getenv("WORKFLOW_STORAGE", "workflows/")
        )

@dataclass
class QuantumSentinelConfig:
    """Main QuantumSentinel configuration"""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    workflow: WorkflowConfig = field(default_factory=WorkflowConfig)

    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    data_dir: Path = field(default_factory=lambda: Path("data"))
    logs_dir: Path = field(default_factory=lambda: Path("logs"))
    reports_dir: Path = field(default_factory=lambda: Path("reports"))
    uploads_dir: Path = field(default_factory=lambda: Path("uploads"))

    # Engine settings
    bandit_path: str = "bandit"
    ghidra_path: str = "/opt/ghidra"
    frida_enabled: bool = True

    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        return cls(
            database=DatabaseConfig.from_env(),
            security=SecurityConfig.from_env(),
            ai=AIConfig.from_env(),
            workflow=WorkflowConfig.from_env(),
            project_root=Path(os.getenv("PROJECT_ROOT", Path(__file__).parent.parent)),
            data_dir=Path(os.getenv("DATA_DIR", "data")),
            logs_dir=Path(os.getenv("LOGS_DIR", "logs")),
            reports_dir=Path(os.getenv("REPORTS_DIR", "reports")),
            uploads_dir=Path(os.getenv("UPLOADS_DIR", "uploads")),
            bandit_path=os.getenv("BANDIT_PATH", "bandit"),
            ghidra_path=os.getenv("GHIDRA_PATH", "/opt/ghidra"),
            frida_enabled=os.getenv("FRIDA_ENABLED", "true").lower() == "true"
        )

# Global configuration instance
config = QuantumSentinelConfig.from_env()