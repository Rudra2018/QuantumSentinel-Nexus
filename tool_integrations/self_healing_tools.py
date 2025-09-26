#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v5.0 - Self-Healing Tool Manager

Manages all external security tools with self-healing capabilities.
Automatically detects, fixes, and finds alternatives for non-working tools.

Supported Tools:
- SAST: Semgrep, CodeQL, Bandit, ESLint
- DAST: Nuclei, ZAP, Burp, SQLmap
- Binary: Ghidra, BinaryNinja, Radare2, Angr
- Fuzzing: AFL++, LibFuzzer, Honggfuzz, Boofuzz
- Mobile: Frida, Objection, MobSF, APKTool
"""

import asyncio
import logging
import subprocess
import shutil
import os
import json
import tempfile
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import platform
import hashlib


class ToolHealthStatus:
    """Represents the health status of a security tool"""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.is_available = False
        self.is_functional = False
        self.version = None
        self.installation_path = None
        self.last_check = None
        self.error_message = None
        self.alternative_tools = []
        self.health_score = 0.0


class SelfHealingToolManager:
    """
    Self-Healing Tool Manager for QuantumSentinel-Nexus

    Provides automatic tool management with self-healing capabilities:
    1. Health checking for all tools
    2. Automatic installation/update
    3. Configuration error detection and fixing
    4. Alternative tool discovery and deployment
    """

    def __init__(self):
        self.logger = logging.getLogger("QuantumSentinel.ToolManager")

        # Tool registry with metadata
        self.tool_registry = self._initialize_tool_registry()

        # Tool health status tracking
        self.tool_status = {}

        # Alternative tool mappings
        self.tool_alternatives = self._initialize_alternatives()

        # Installation methods
        self.installation_methods = self._initialize_installation_methods()

        # Health check cache
        self.health_check_cache = {}
        self.cache_duration = timedelta(minutes=30)

        # Initialize tool status
        self._initialize_tool_status()

    def _initialize_tool_registry(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive tool registry"""
        return {
            # Static Analysis Tools (SAST)
            'semgrep': {
                'category': 'sast',
                'description': 'Static analysis tool for finding bugs and security issues',
                'check_command': ['semgrep', '--version'],
                'install_methods': ['pip', 'brew', 'binary'],
                'config_files': ['.semgrep.yml', '.semgrep/'],
                'priority': 1
            },
            'codeql': {
                'category': 'sast',
                'description': 'GitHub\'s semantic code analysis engine',
                'check_command': ['codeql', 'version'],
                'install_methods': ['binary', 'github'],
                'config_files': ['codeql-config.yml'],
                'priority': 2
            },
            'bandit': {
                'category': 'sast',
                'description': 'Python security linter',
                'check_command': ['bandit', '--version'],
                'install_methods': ['pip'],
                'config_files': ['.bandit', 'bandit.yaml'],
                'priority': 3
            },

            # Dynamic Analysis Tools (DAST)
            'nuclei': {
                'category': 'dast',
                'description': 'Fast vulnerability scanner',
                'check_command': ['nuclei', '-version'],
                'install_methods': ['go', 'binary', 'brew'],
                'config_files': ['nuclei-config.yaml'],
                'priority': 1
            },
            'zap': {
                'category': 'dast',
                'description': 'OWASP ZAP security scanner',
                'check_command': ['zap.sh', '-version'],
                'install_methods': ['binary', 'docker'],
                'config_files': ['zap-config.xml'],
                'priority': 2
            },
            'sqlmap': {
                'category': 'dast',
                'description': 'SQL injection testing tool',
                'check_command': ['sqlmap', '--version'],
                'install_methods': ['git', 'pip'],
                'config_files': ['sqlmap.conf'],
                'priority': 3
            },

            # Binary Analysis Tools
            'ghidra': {
                'category': 'binary',
                'description': 'NSA reverse engineering framework',
                'check_command': ['ghidra', '-help'],
                'install_methods': ['binary', 'brew'],
                'config_files': ['ghidra_scripts/'],
                'priority': 1
            },
            'angr': {
                'category': 'binary',
                'description': 'Binary analysis platform',
                'check_command': ['python3', '-c', 'import angr; print(angr.__version__)'],
                'install_methods': ['pip', 'conda'],
                'config_files': [],
                'priority': 2
            },
            'radare2': {
                'category': 'binary',
                'description': 'Reverse engineering framework',
                'check_command': ['r2', '-v'],
                'install_methods': ['binary', 'brew', 'git'],
                'config_files': ['.radare2rc'],
                'priority': 3
            },

            # Fuzzing Tools
            'afl++': {
                'category': 'fuzzing',
                'description': 'American Fuzzy Lop++ fuzzer',
                'check_command': ['afl-fuzz', '-h'],
                'install_methods': ['compile', 'brew'],
                'config_files': ['afl_config'],
                'priority': 1
            },
            'honggfuzz': {
                'category': 'fuzzing',
                'description': 'Security-oriented fuzzer',
                'check_command': ['honggfuzz', '--help'],
                'install_methods': ['compile', 'brew'],
                'config_files': ['honggfuzz.cfg'],
                'priority': 2
            },

            # Mobile Analysis Tools
            'frida': {
                'category': 'mobile',
                'description': 'Dynamic instrumentation toolkit',
                'check_command': ['frida', '--version'],
                'install_methods': ['pip', 'npm'],
                'config_files': ['frida-scripts/'],
                'priority': 1
            },
            'objection': {
                'category': 'mobile',
                'description': 'Mobile runtime exploration toolkit',
                'check_command': ['objection', 'version'],
                'install_methods': ['pip'],
                'config_files': [],
                'priority': 2
            },
            'mobsf': {
                'category': 'mobile',
                'description': 'Mobile Security Framework',
                'check_command': ['mobsf', '--help'],
                'install_methods': ['pip', 'docker'],
                'config_files': ['mobsf_config.py'],
                'priority': 3
            }
        }

    def _initialize_alternatives(self) -> Dict[str, List[str]]:
        """Initialize alternative tool mappings"""
        return {
            'sast': ['semgrep', 'codeql', 'bandit', 'eslint', 'flawfinder'],
            'dast': ['nuclei', 'zap', 'burp', 'sqlmap', 'dirb'],
            'binary': ['ghidra', 'radare2', 'angr', 'binaryninja', 'ida'],
            'fuzzing': ['afl++', 'honggfuzz', 'libfuzzer', 'boofuzz', 'peach'],
            'mobile': ['frida', 'objection', 'mobsf', 'apktool', 'jadx']
        }

    def _initialize_installation_methods(self) -> Dict[str, Dict[str, Any]]:
        """Initialize installation method configurations"""
        return {
            'pip': {
                'command_template': ['pip3', 'install', '{tool_name}'],
                'platforms': ['darwin', 'linux', 'win32'],
                'pre_check': ['python3', '--version']
            },
            'brew': {
                'command_template': ['brew', 'install', '{tool_name}'],
                'platforms': ['darwin'],
                'pre_check': ['brew', '--version']
            },
            'go': {
                'command_template': ['go', 'install', '{install_path}@latest'],
                'platforms': ['darwin', 'linux', 'win32'],
                'pre_check': ['go', 'version']
            },
            'npm': {
                'command_template': ['npm', 'install', '-g', '{tool_name}'],
                'platforms': ['darwin', 'linux', 'win32'],
                'pre_check': ['npm', '--version']
            },
            'binary': {
                'command_template': ['curl', '-L', '{download_url}', '-o', '{output_file}'],
                'platforms': ['darwin', 'linux', 'win32'],
                'pre_check': ['curl', '--version']
            }
        }

    def _initialize_tool_status(self):
        """Initialize tool status tracking"""
        for tool_name in self.tool_registry:
            self.tool_status[tool_name] = ToolHealthStatus(tool_name)

    async def health_check_all_tools(self) -> Dict[str, ToolHealthStatus]:
        """Perform comprehensive health check on all tools"""
        self.logger.info("🔧 Performing comprehensive tool health check")

        health_check_tasks = []

        for tool_name in self.tool_registry:
            task = self._health_check_tool(tool_name)
            health_check_tasks.append((tool_name, task))

        # Execute health checks concurrently
        results = {}
        for tool_name, task in health_check_tasks:
            try:
                status = await task
                results[tool_name] = status
                self.tool_status[tool_name] = status
            except Exception as e:
                self.logger.error(f"Health check failed for {tool_name}: {e}")
                self.tool_status[tool_name].error_message = str(e)

        # Log health check summary
        healthy_tools = len([s for s in results.values() if s.is_functional])
        total_tools = len(results)

        self.logger.info(f"Health check complete: {healthy_tools}/{total_tools} tools functional")

        return results

    async def _health_check_tool(self, tool_name: str) -> ToolHealthStatus:
        """Perform detailed health check on specific tool"""
        status = ToolHealthStatus(tool_name)
        tool_config = self.tool_registry.get(tool_name, {})

        try:
            # Check cache first
            if self._is_health_check_cached(tool_name):
                return self.health_check_cache[tool_name]

            # Check if tool is available in PATH
            status.installation_path = shutil.which(tool_name)
            status.is_available = status.installation_path is not None

            if status.is_available:
                # Test tool functionality
                check_command = tool_config.get('check_command', [tool_name, '--version'])

                try:
                    result = await asyncio.create_subprocess_exec(
                        *check_command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await result.communicate()

                    if result.returncode == 0:
                        status.is_functional = True
                        status.version = self._extract_version(stdout.decode() + stderr.decode())
                        status.health_score = 1.0
                    else:
                        status.error_message = stderr.decode().strip()
                        status.health_score = 0.3

                except Exception as e:
                    status.error_message = f"Command execution failed: {e}"
                    status.health_score = 0.1
            else:
                status.error_message = f"Tool not found in PATH"
                status.health_score = 0.0

            # Check configuration files
            await self._check_tool_configuration(status, tool_config)

            # Update cache and timestamp
            status.last_check = datetime.now()
            self.health_check_cache[tool_name] = status

        except Exception as e:
            status.error_message = f"Health check failed: {e}"
            status.health_score = 0.0

        return status

    async def _check_tool_configuration(self, status: ToolHealthStatus, tool_config: Dict[str, Any]):
        """Check tool configuration files and settings"""
        try:
            config_files = tool_config.get('config_files', [])

            for config_file in config_files:
                config_path = Path(config_file)

                # Check in common locations
                search_paths = [
                    Path.home() / config_file,
                    Path.cwd() / config_file,
                    Path('/etc') / config_file,
                    Path('/usr/local/etc') / config_file
                ]

                config_found = any(path.exists() for path in search_paths)

                if config_found:
                    status.health_score = min(1.0, status.health_score + 0.1)
                else:
                    # Create default configuration if needed
                    await self._create_default_config(status.tool_name, config_file)

        except Exception as e:
            self.logger.warning(f"Configuration check failed for {status.tool_name}: {e}")

    async def _create_default_config(self, tool_name: str, config_file: str):
        """Create default configuration for tool"""
        try:
            config_templates = {
                'nuclei-config.yaml': '''
# QuantumSentinel-Nexus Nuclei Configuration
update-templates: true
update-directory: ~/.nuclei-templates/
silent: false
verbose: true
no-color: false
''',
                '.semgrep.yml': '''
# QuantumSentinel-Nexus Semgrep Configuration
rules:
  - id: security-scan
    patterns:
      - pattern: $X
    languages: [python, javascript, go, java]
    severity: INFO
'''
            }

            if config_file in config_templates:
                config_path = Path.home() / config_file
                config_path.parent.mkdir(parents=True, exist_ok=True)

                with open(config_path, 'w') as f:
                    f.write(config_templates[config_file])

                self.logger.info(f"Created default configuration: {config_path}")

        except Exception as e:
            self.logger.error(f"Default config creation failed: {e}")

    def _is_health_check_cached(self, tool_name: str) -> bool:
        """Check if health check result is cached and valid"""
        if tool_name not in self.health_check_cache:
            return False

        cached_status = self.health_check_cache[tool_name]
        if cached_status.last_check is None:
            return False

        return datetime.now() - cached_status.last_check < self.cache_duration

    def _extract_version(self, output: str) -> Optional[str]:
        """Extract version from tool output"""
        try:
            import re

            # Common version patterns
            patterns = [
                r'v?(\d+\.\d+\.\d+)',
                r'version\s+(\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    return match.group(1)

        except Exception:
            pass

        return None

    async def auto_heal_tools(self) -> Dict[str, Any]:
        """Automatically heal broken or missing tools"""
        self.logger.info("🛠️ Initiating automatic tool healing")

        healing_results = {
            'attempted': [],
            'successful': [],
            'failed': [],
            'alternatives_deployed': []
        }

        # First, perform health check
        health_status = await self.health_check_all_tools()

        # Identify tools needing healing
        broken_tools = [
            name for name, status in health_status.items()
            if not status.is_functional
        ]

        for tool_name in broken_tools:
            healing_results['attempted'].append(tool_name)

            try:
                # Attempt to heal the tool
                if await self._heal_tool(tool_name):
                    healing_results['successful'].append(tool_name)
                else:
                    # Try to deploy alternative
                    alternative = await self._deploy_alternative_tool(tool_name)
                    if alternative:
                        healing_results['alternatives_deployed'].append({
                            'original': tool_name,
                            'alternative': alternative
                        })
                    else:
                        healing_results['failed'].append(tool_name)

            except Exception as e:
                self.logger.error(f"Healing failed for {tool_name}: {e}")
                healing_results['failed'].append(tool_name)

        self.logger.info(f"Auto-healing complete. Success: {len(healing_results['successful'])}, "
                        f"Alternatives: {len(healing_results['alternatives_deployed'])}, "
                        f"Failed: {len(healing_results['failed'])}")

        return healing_results

    async def _heal_tool(self, tool_name: str) -> bool:
        """Attempt to heal a specific tool"""
        tool_config = self.tool_registry.get(tool_name, {})

        # Try reinstallation
        if await self._reinstall_tool(tool_name):
            return True

        # Try configuration fixes
        if await self._fix_tool_configuration(tool_name):
            return True

        # Try updating
        if await self._update_tool(tool_name):
            return True

        return False

    async def _reinstall_tool(self, tool_name: str) -> bool:
        """Attempt to reinstall a tool"""
        tool_config = self.tool_registry.get(tool_name, {})
        install_methods = tool_config.get('install_methods', [])

        for method in install_methods:
            try:
                if await self._install_via_method(tool_name, method):
                    self.logger.info(f"Successfully reinstalled {tool_name} via {method}")
                    return True
            except Exception as e:
                self.logger.warning(f"Installation via {method} failed for {tool_name}: {e}")

        return False

    async def _install_via_method(self, tool_name: str, method: str) -> bool:
        """Install tool using specific method"""
        method_config = self.installation_methods.get(method, {})

        # Check if method is supported on current platform
        current_platform = platform.system().lower()
        if current_platform not in method_config.get('platforms', []):
            return False

        # Check method prerequisites
        pre_check = method_config.get('pre_check', [])
        if pre_check:
            try:
                result = await asyncio.create_subprocess_exec(
                    *pre_check,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                if (await result.wait()) != 0:
                    return False
            except Exception:
                return False

        # Execute installation
        try:
            command_template = method_config.get('command_template', [])
            install_command = [
                cmd.format(tool_name=tool_name) if '{tool_name}' in cmd else cmd
                for cmd in command_template
            ]

            result = await asyncio.create_subprocess_exec(
                *install_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            return (await result.wait()) == 0

        except Exception as e:
            self.logger.error(f"Installation command failed: {e}")
            return False

    async def _fix_tool_configuration(self, tool_name: str) -> bool:
        """Attempt to fix tool configuration issues"""
        try:
            # Recreate default configurations
            tool_config = self.tool_registry.get(tool_name, {})
            config_files = tool_config.get('config_files', [])

            for config_file in config_files:
                await self._create_default_config(tool_name, config_file)

            # Test functionality after config fix
            status = await self._health_check_tool(tool_name)
            return status.is_functional

        except Exception as e:
            self.logger.error(f"Configuration fix failed for {tool_name}: {e}")
            return False

    async def _update_tool(self, tool_name: str) -> bool:
        """Attempt to update tool to latest version"""
        # Implementation depends on tool type
        try:
            # Try common update methods
            update_commands = [
                ['pip3', 'install', '--upgrade', tool_name],
                ['brew', 'upgrade', tool_name],
                ['go', 'install', f'{tool_name}@latest']
            ]

            for command in update_commands:
                try:
                    result = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    if (await result.wait()) == 0:
                        return True
                except Exception:
                    continue

        except Exception as e:
            self.logger.error(f"Update failed for {tool_name}: {e}")

        return False

    async def _deploy_alternative_tool(self, broken_tool: str) -> Optional[str]:
        """Deploy alternative tool for broken one"""
        tool_config = self.tool_registry.get(broken_tool, {})
        category = tool_config.get('category')

        if not category:
            return None

        # Get alternatives for this category
        alternatives = self.tool_alternatives.get(category, [])

        # Remove the broken tool from alternatives
        alternatives = [alt for alt in alternatives if alt != broken_tool]

        # Try to install and test alternatives
        for alternative in alternatives:
            if alternative in self.tool_registry:
                try:
                    if await self._reinstall_tool(alternative):
                        alt_status = await self._health_check_tool(alternative)
                        if alt_status.is_functional:
                            self.logger.info(f"Deployed alternative {alternative} for {broken_tool}")
                            return alternative
                except Exception as e:
                    self.logger.warning(f"Alternative {alternative} deployment failed: {e}")

        return None

    async def get_tool_for_task(self, task_type: str, task_requirements: Dict[str, Any] = None) -> Optional[str]:
        """Get best available tool for specific task"""
        category_mapping = {
            'static_analysis': 'sast',
            'dynamic_analysis': 'dast',
            'binary_analysis': 'binary',
            'fuzzing': 'fuzzing',
            'mobile_analysis': 'mobile'
        }

        category = category_mapping.get(task_type)
        if not category:
            return None

        # Get tools in category, sorted by priority
        category_tools = [
            (name, config) for name, config in self.tool_registry.items()
            if config.get('category') == category
        ]

        category_tools.sort(key=lambda x: x[1].get('priority', 999))

        # Find first functional tool
        for tool_name, _ in category_tools:
            status = self.tool_status.get(tool_name)
            if status and status.is_functional:
                return tool_name

        # If no functional tool found, try auto-healing
        for tool_name, _ in category_tools:
            if await self._heal_tool(tool_name):
                return tool_name

        return None

    async def execute_tool_command(self, tool_name: str, command: List[str], **kwargs) -> Tuple[int, str, str]:
        """Execute tool command with error handling and fallbacks"""
        try:
            # Ensure tool is functional
            if not await self._ensure_tool_functional(tool_name):
                raise Exception(f"Tool {tool_name} is not functional")

            # Execute command
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **kwargs
            )

            stdout, stderr = await process.communicate()
            return process.returncode, stdout.decode(), stderr.decode()

        except Exception as e:
            self.logger.error(f"Tool command execution failed for {tool_name}: {e}")
            return -1, "", str(e)

    async def _ensure_tool_functional(self, tool_name: str) -> bool:
        """Ensure tool is functional, heal if necessary"""
        status = self.tool_status.get(tool_name)

        if not status or not status.is_functional:
            # Try to heal the tool
            if await self._heal_tool(tool_name):
                # Update status
                self.tool_status[tool_name] = await self._health_check_tool(tool_name)
                return self.tool_status[tool_name].is_functional
            return False

        return True

    def get_tool_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive tool status summary"""
        summary = {
            'total_tools': len(self.tool_status),
            'functional_tools': 0,
            'broken_tools': 0,
            'unknown_status': 0,
            'categories': {},
            'last_health_check': None
        }

        for tool_name, status in self.tool_status.items():
            tool_config = self.tool_registry.get(tool_name, {})
            category = tool_config.get('category', 'unknown')

            if category not in summary['categories']:
                summary['categories'][category] = {
                    'total': 0,
                    'functional': 0,
                    'tools': []
                }

            summary['categories'][category]['total'] += 1
            summary['categories'][category]['tools'].append({
                'name': tool_name,
                'functional': status.is_functional,
                'version': status.version,
                'health_score': status.health_score
            })

            if status.is_functional:
                summary['functional_tools'] += 1
                summary['categories'][category]['functional'] += 1
            elif status.last_check:
                summary['broken_tools'] += 1
            else:
                summary['unknown_status'] += 1

            if status.last_check:
                if not summary['last_health_check'] or status.last_check > summary['last_health_check']:
                    summary['last_health_check'] = status.last_check

        return summary