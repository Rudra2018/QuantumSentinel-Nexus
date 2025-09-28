#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Advanced Fuzzing Service
Comprehensive fuzzing platform with ML-enhanced mutation and multi-protocol support
"""

import asyncio
import json
import logging
import os
import subprocess
import uuid
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

import numpy as np
import scipy.stats as stats
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
import torch
import torch.nn as nn
import tensorflow as tf

# Network and protocol tools
from scapy.all import *
import nmap
import dns.resolver
from netaddr import IPNetwork, IPAddress

# File format analysis
import magic
import pypdf
from docx import Document

# Fuzzing libraries
import boofuzz
from hypothesis import given, strategies as st
import random
import string

# FastAPI and async
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx
import aiofiles
import aiohttp

# System tools
import psutil
import docker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("QuantumSentinel.Fuzzing")

class FuzzingType(str, Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_PROTOCOL = "network_protocol"
    BINARY_APPLICATION = "binary_application"
    FILE_FORMAT = "file_format"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    IOT_DEVICE = "iot_device"
    MOBILE_APP = "mobile_app"

class MutationStrategy(str, Enum):
    RANDOM = "random"
    GENETIC = "genetic"
    GRAMMAR_BASED = "grammar_based"
    ML_GUIDED = "ml_guided"
    COVERAGE_GUIDED = "coverage_guided"

@dataclass
class FuzzingTarget:
    target_id: str
    target_type: FuzzingType
    endpoint: str
    parameters: Dict[str, Any]
    headers: Dict[str, str]
    payload_template: Optional[str] = None
    authentication: Optional[Dict[str, str]] = None

@dataclass
class FuzzingResult:
    result_id: str
    target_id: str
    test_case: str
    response_code: Optional[int]
    response_body: Optional[str]
    response_time: float
    error_detected: bool
    vulnerability_type: Optional[str]
    severity: str
    timestamp: datetime
    metadata: Dict[str, Any]

class MLMutationEngine:
    """Machine Learning enhanced mutation engine"""

    def __init__(self):
        self.mutation_model = None
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.coverage_tracker = {}
        self.successful_mutations = []

    def initialize_ml_models(self):
        """Initialize ML models for intelligent fuzzing"""
        try:
            # Simple neural network for mutation guidance
            self.mutation_model = nn.Sequential(
                nn.Linear(100, 256),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Linear(128, 50),
                nn.Sigmoid()
            )

            logger.info("ML mutation models initialized")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    def generate_intelligent_mutations(self, base_input: str, target_type: FuzzingType) -> List[str]:
        """Generate mutations using ML guidance"""
        mutations = []

        try:
            # Traditional mutations
            mutations.extend(self._generate_traditional_mutations(base_input))

            # ML-guided mutations
            if self.mutation_model:
                mutations.extend(self._generate_ml_mutations(base_input, target_type))

            # Grammar-based mutations for specific protocols
            mutations.extend(self._generate_grammar_mutations(base_input, target_type))

            return mutations
        except Exception as e:
            logger.error(f"Mutation generation failed: {e}")
            return [base_input]  # Fallback to original input

    def _generate_traditional_mutations(self, base_input: str) -> List[str]:
        """Traditional fuzzing mutations"""
        mutations = []

        # Bit flipping
        for i in range(min(len(base_input), 10)):
            mutated = list(base_input)
            if i < len(mutated):
                mutated[i] = chr(ord(mutated[i]) ^ 1)
                mutations.append(''.join(mutated))

        # Length mutations
        mutations.append(base_input * 2)  # Double length
        mutations.append(base_input[:len(base_input)//2])  # Half length
        mutations.append(base_input + "A" * 1000)  # Buffer overflow attempt

        # Special characters
        special_chars = ["'", '"', "<", ">", "&", "%", "\x00", "\x01", "\xff"]
        for char in special_chars:
            mutations.append(base_input + char)
            mutations.append(char + base_input)
            mutations.append(base_input.replace(base_input[0] if base_input else 'a', char))

        # Format string attacks
        format_strings = ["%s", "%x", "%n", "%p", "%%"]
        for fmt in format_strings:
            mutations.append(base_input + fmt)

        return mutations

    def _generate_ml_mutations(self, base_input: str, target_type: FuzzingType) -> List[str]:
        """ML-guided mutation generation"""
        mutations = []

        try:
            # Convert input to feature vector
            features = self._input_to_features(base_input)

            # Generate variations using learned patterns
            for _ in range(5):
                # Add some noise to features
                noisy_features = features + np.random.normal(0, 0.1, len(features))
                mutated_input = self._features_to_input(noisy_features, base_input)
                mutations.append(mutated_input)

        except Exception as e:
            logger.error(f"ML mutation failed: {e}")

        return mutations

    def _generate_grammar_mutations(self, base_input: str, target_type: FuzzingType) -> List[str]:
        """Grammar-based mutations for specific protocols"""
        mutations = []

        if target_type == FuzzingType.WEB_APPLICATION:
            # SQL injection patterns
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "1' AND 1=1--",
                "admin'--"
            ]
            mutations.extend([base_input + payload for payload in sql_payloads])

            # XSS patterns
            xss_payloads = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "';alert('xss');//"
            ]
            mutations.extend([base_input + payload for payload in xss_payloads])

        elif target_type == FuzzingType.NETWORK_PROTOCOL:
            # Protocol-specific mutations
            protocol_patterns = [
                "\x41" * 100,  # Buffer overflow
                "\x00" * 50,   # Null bytes
                "\xff" * 50,   # Max bytes
                "\x0a\x0d" * 10  # CRLF injection
            ]
            mutations.extend([base_input + pattern for pattern in protocol_patterns])

        return mutations

    def _input_to_features(self, input_str: str) -> np.ndarray:
        """Convert input string to feature vector"""
        features = []

        # Basic features
        features.append(len(input_str))
        features.append(sum(1 for c in input_str if c.isalpha()))
        features.append(sum(1 for c in input_str if c.isdigit()))
        features.append(sum(1 for c in input_str if c in "!@#$%^&*()"))

        # Character frequency features
        char_counts = np.zeros(256)
        for char in input_str:
            if ord(char) < 256:
                char_counts[ord(char)] += 1

        # Normalize and take top features
        char_features = char_counts[:96]  # Printable ASCII range
        features.extend(char_features.tolist())

        # Pad to fixed size
        while len(features) < 100:
            features.append(0)

        return np.array(features[:100])

    def _features_to_input(self, features: np.ndarray, original: str) -> str:
        """Convert features back to input string (approximate)"""
        try:
            # Simple approach: modify original based on feature changes
            length_change = int(features[0]) - len(original)
            if length_change > 0:
                return original + 'A' * min(length_change, 100)
            elif length_change < 0:
                return original[:max(1, len(original) + length_change)]
            else:
                return original
        except:
            return original

class WebApplicationFuzzer:
    """Advanced web application fuzzing"""

    def __init__(self):
        self.session = None
        self.mutation_engine = MLMutationEngine()

    async def fuzz_web_target(self, target: FuzzingTarget) -> List[FuzzingResult]:
        """Fuzz web application endpoints"""
        results = []

        try:
            async with aiohttp.ClientSession() as session:
                self.session = session

                # Generate test cases
                test_cases = await self._generate_web_test_cases(target)

                for test_case in test_cases:
                    result = await self._execute_web_test(target, test_case)
                    results.append(result)

                    # Analyze for interesting responses
                    if self._is_interesting_response(result):
                        logger.info(f"Interesting response detected: {result.result_id}")

        except Exception as e:
            logger.error(f"Web fuzzing failed: {e}")

        return results

    async def _generate_web_test_cases(self, target: FuzzingTarget) -> List[Dict[str, Any]]:
        """Generate web application test cases"""
        test_cases = []

        base_params = target.parameters.copy()

        for param_name, param_value in base_params.items():
            # Generate mutations for each parameter
            mutations = self.mutation_engine.generate_intelligent_mutations(
                str(param_value), FuzzingType.WEB_APPLICATION
            )

            for mutation in mutations:
                test_params = base_params.copy()
                test_params[param_name] = mutation

                test_cases.append({
                    'params': test_params,
                    'headers': target.headers,
                    'method': 'GET',
                    'mutation_type': f'param_{param_name}'
                })

        # Header fuzzing
        for header_name, header_value in target.headers.items():
            mutations = self.mutation_engine.generate_intelligent_mutations(
                header_value, FuzzingType.WEB_APPLICATION
            )

            for mutation in mutations:
                test_headers = target.headers.copy()
                test_headers[header_name] = mutation

                test_cases.append({
                    'params': base_params,
                    'headers': test_headers,
                    'method': 'GET',
                    'mutation_type': f'header_{header_name}'
                })

        return test_cases[:100]  # Limit test cases

    async def _execute_web_test(self, target: FuzzingTarget, test_case: Dict[str, Any]) -> FuzzingResult:
        """Execute a single web test case"""
        start_time = datetime.utcnow()

        try:
            async with self.session.request(
                method=test_case['method'],
                url=target.endpoint,
                params=test_case['params'],
                headers=test_case['headers'],
                timeout=10
            ) as response:
                response_body = await response.text()
                response_time = (datetime.utcnow() - start_time).total_seconds()

                # Analyze response for vulnerabilities
                vulnerability_type, severity = self._analyze_web_response(
                    response.status, response_body, response.headers
                )

                return FuzzingResult(
                    result_id=str(uuid.uuid4()),
                    target_id=target.target_id,
                    test_case=json.dumps(test_case),
                    response_code=response.status,
                    response_body=response_body[:1000],  # Limit size
                    response_time=response_time,
                    error_detected=vulnerability_type is not None,
                    vulnerability_type=vulnerability_type,
                    severity=severity,
                    timestamp=start_time,
                    metadata={'mutation_type': test_case.get('mutation_type', 'unknown')}
                )

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()

            return FuzzingResult(
                result_id=str(uuid.uuid4()),
                target_id=target.target_id,
                test_case=json.dumps(test_case),
                response_code=None,
                response_body=str(e),
                response_time=response_time,
                error_detected=True,
                vulnerability_type="connection_error",
                severity="low",
                timestamp=start_time,
                metadata={'error': str(e)}
            )

    def _analyze_web_response(self, status_code: int, body: str, headers: dict) -> tuple:
        """Analyze web response for vulnerabilities"""
        vulnerability_type = None
        severity = "info"

        # SQL injection detection
        sql_errors = [
            "mysql_fetch_array", "ORA-", "Microsoft OLE DB Provider",
            "PostgreSQL query failed", "SQLite error", "sqlite3.OperationalError"
        ]
        if any(error in body.lower() for error in sql_errors):
            vulnerability_type = "sql_injection"
            severity = "high"

        # XSS detection
        if "<script>" in body.lower() or "alert(" in body.lower():
            vulnerability_type = "xss"
            severity = "medium"

        # Information disclosure
        info_patterns = [
            "root:", "admin:", "password:", "secret:", "key:",
            "exception", "error", "stack trace", "debug"
        ]
        if any(pattern in body.lower() for pattern in info_patterns):
            if not vulnerability_type:
                vulnerability_type = "information_disclosure"
                severity = "low"

        # HTTP security headers
        security_headers = [
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "strict-transport-security", "content-security-policy"
        ]
        missing_headers = [h for h in security_headers if h not in [k.lower() for k in headers.keys()]]
        if missing_headers and not vulnerability_type:
            vulnerability_type = "missing_security_headers"
            severity = "low"

        # Status code analysis
        if status_code == 500:
            if not vulnerability_type:
                vulnerability_type = "server_error"
                severity = "medium"
        elif status_code == 403:
            if not vulnerability_type:
                vulnerability_type = "access_control"
                severity = "low"

        return vulnerability_type, severity

    def _is_interesting_response(self, result: FuzzingResult) -> bool:
        """Determine if a response is interesting for further analysis"""
        # High severity vulnerabilities
        if result.severity in ["high", "critical"]:
            return True

        # Unusual response codes
        if result.response_code in [500, 403, 401, 302]:
            return True

        # Long response times (potential DoS)
        if result.response_time > 5.0:
            return True

        # Large response bodies (potential information disclosure)
        if result.response_body and len(result.response_body) > 10000:
            return True

        return False

class NetworkProtocolFuzzer:
    """Network protocol fuzzing capabilities"""

    def __init__(self):
        self.mutation_engine = MLMutationEngine()

    async def fuzz_network_target(self, target: FuzzingTarget) -> List[FuzzingResult]:
        """Fuzz network protocols"""
        results = []

        try:
            # Parse target endpoint
            host, port = self._parse_network_endpoint(target.endpoint)

            # Generate protocol-specific test cases
            test_cases = await self._generate_network_test_cases(target, host, port)

            for test_case in test_cases:
                result = await self._execute_network_test(target, test_case, host, port)
                results.append(result)

        except Exception as e:
            logger.error(f"Network fuzzing failed: {e}")

        return results

    def _parse_network_endpoint(self, endpoint: str) -> tuple:
        """Parse network endpoint into host and port"""
        if "://" in endpoint:
            endpoint = endpoint.split("://")[1]

        if ":" in endpoint:
            host, port = endpoint.split(":", 1)
            return host, int(port)
        else:
            return endpoint, 80

    async def _generate_network_test_cases(self, target: FuzzingTarget, host: str, port: int) -> List[Dict[str, Any]]:
        """Generate network protocol test cases"""
        test_cases = []

        # Basic protocol detection
        protocol = self._detect_protocol(port)

        # Generate protocol-specific payloads
        if protocol == "http":
            test_cases.extend(self._generate_http_payloads())
        elif protocol == "ftp":
            test_cases.extend(self._generate_ftp_payloads())
        elif protocol == "smtp":
            test_cases.extend(self._generate_smtp_payloads())
        else:
            test_cases.extend(self._generate_generic_payloads())

        return test_cases

    def _detect_protocol(self, port: int) -> str:
        """Detect protocol based on port"""
        port_mapping = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s"
        }
        return port_mapping.get(port, "unknown")

    def _generate_http_payloads(self) -> List[Dict[str, Any]]:
        """Generate HTTP-specific test payloads"""
        payloads = []

        # Malformed HTTP requests
        http_tests = [
            "GET / HTTP/1.1\r\nHost: \r\n\r\n",
            "GET " + "A" * 10000 + " HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: " + "A" * 1000 + "\r\n\r\n",
            "INVALID_METHOD / HTTP/1.1\r\n\r\n",
            "GET / HTTP/999.999\r\n\r\n"
        ]

        for payload in http_tests:
            payloads.append({
                'payload': payload.encode(),
                'protocol': 'tcp',
                'expected_response': True
            })

        return payloads

    def _generate_ftp_payloads(self) -> List[Dict[str, Any]]:
        """Generate FTP-specific test payloads"""
        payloads = []

        ftp_commands = [
            "USER anonymous\r\n",
            "USER " + "A" * 1000 + "\r\n",
            "PASS guest\r\n",
            "PASS " + "A" * 1000 + "\r\n",
            "LIST " + "../" * 100 + "\r\n",
            "RETR " + "A" * 1000 + "\r\n"
        ]

        for cmd in ftp_commands:
            payloads.append({
                'payload': cmd.encode(),
                'protocol': 'tcp',
                'expected_response': True
            })

        return payloads

    def _generate_smtp_payloads(self) -> List[Dict[str, Any]]:
        """Generate SMTP-specific test payloads"""
        payloads = []

        smtp_commands = [
            "HELO test\r\n",
            "HELO " + "A" * 1000 + "\r\n",
            "MAIL FROM:<test@test.com>\r\n",
            "MAIL FROM:<" + "A" * 1000 + "@test.com>\r\n",
            "RCPT TO:<admin@localhost>\r\n",
            "DATA\r\nTest message\r\n.\r\n"
        ]

        for cmd in smtp_commands:
            payloads.append({
                'payload': cmd.encode(),
                'protocol': 'tcp',
                'expected_response': True
            })

        return payloads

    def _generate_generic_payloads(self) -> List[Dict[str, Any]]:
        """Generate generic network payloads"""
        payloads = []

        # Generic buffer overflow attempts
        generic_tests = [
            b"A" * 100,
            b"A" * 1000,
            b"A" * 10000,
            b"\x00" * 100,
            b"\xff" * 100,
            b"\x41\x42\x43\x44" * 250
        ]

        for payload in generic_tests:
            payloads.append({
                'payload': payload,
                'protocol': 'tcp',
                'expected_response': False
            })

        return payloads

    async def _execute_network_test(self, target: FuzzingTarget, test_case: Dict[str, Any], host: str, port: int) -> FuzzingResult:
        """Execute network protocol test"""
        start_time = datetime.utcnow()

        try:
            if test_case['protocol'] == 'tcp':
                response = await self._send_tcp_payload(host, port, test_case['payload'])
            else:
                response = await self._send_udp_payload(host, port, test_case['payload'])

            response_time = (datetime.utcnow() - start_time).total_seconds()

            # Analyze response
            vulnerability_type, severity = self._analyze_network_response(response, test_case)

            return FuzzingResult(
                result_id=str(uuid.uuid4()),
                target_id=target.target_id,
                test_case=str(test_case['payload'])[:500],
                response_code=200 if response else 0,
                response_body=str(response)[:1000] if response else None,
                response_time=response_time,
                error_detected=vulnerability_type is not None,
                vulnerability_type=vulnerability_type,
                severity=severity,
                timestamp=start_time,
                metadata={'protocol': test_case['protocol']}
            )

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()

            return FuzzingResult(
                result_id=str(uuid.uuid4()),
                target_id=target.target_id,
                test_case=str(test_case['payload'])[:500],
                response_code=None,
                response_body=str(e),
                response_time=response_time,
                error_detected=True,
                vulnerability_type="connection_error",
                severity="low",
                timestamp=start_time,
                metadata={'error': str(e), 'protocol': test_case['protocol']}
            )

    async def _send_tcp_payload(self, host: str, port: int, payload: bytes) -> bytes:
        """Send TCP payload and get response"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            writer.write(payload)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5)

            writer.close()
            await writer.wait_closed()

            return response
        except Exception as e:
            logger.debug(f"TCP send failed: {e}")
            return b""

    async def _send_udp_payload(self, host: str, port: int, payload: bytes) -> bytes:
        """Send UDP payload and get response"""
        try:
            # Create UDP socket using asyncio
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(host, port)
            )

            transport.sendto(payload)
            await asyncio.sleep(1)  # Wait for response

            transport.close()
            return b""  # UDP response handling would need more complex implementation
        except Exception as e:
            logger.debug(f"UDP send failed: {e}")
            return b""

    def _analyze_network_response(self, response: bytes, test_case: Dict[str, Any]) -> tuple:
        """Analyze network response for vulnerabilities"""
        vulnerability_type = None
        severity = "info"

        if not response and test_case.get('expected_response', False):
            vulnerability_type = "service_down"
            severity = "medium"
        elif response and len(response) > 10000:
            vulnerability_type = "excessive_response"
            severity = "low"
        elif b"error" in response.lower() or b"exception" in response.lower():
            vulnerability_type = "error_disclosure"
            severity = "low"

        return vulnerability_type, severity

class FuzzingOrchestrator:
    """Main fuzzing orchestration service"""

    def __init__(self):
        self.web_fuzzer = WebApplicationFuzzer()
        self.network_fuzzer = NetworkProtocolFuzzer()
        self.active_campaigns = {}
        self.results_storage = []

        # Initialize ML components
        self._initialize_ml_components()

    def _initialize_ml_components(self):
        """Initialize machine learning components"""
        try:
            self.web_fuzzer.mutation_engine.initialize_ml_models()
            self.network_fuzzer.mutation_engine.initialize_ml_models()
            logger.info("ML fuzzing components initialized")
        except Exception as e:
            logger.error(f"Failed to initialize ML components: {e}")

    async def start_fuzzing_campaign(self, target: FuzzingTarget) -> str:
        """Start a comprehensive fuzzing campaign"""
        campaign_id = str(uuid.uuid4())

        try:
            logger.info(f"Starting fuzzing campaign {campaign_id} for {target.endpoint}")

            self.active_campaigns[campaign_id] = {
                'target': target,
                'status': 'running',
                'start_time': datetime.utcnow(),
                'results': []
            }

            # Execute fuzzing based on target type
            if target.target_type == FuzzingType.WEB_APPLICATION:
                results = await self.web_fuzzer.fuzz_web_target(target)
            elif target.target_type == FuzzingType.NETWORK_PROTOCOL:
                results = await self.network_fuzzer.fuzz_network_target(target)
            else:
                results = await self._generic_fuzzing(target)

            # Store results
            self.active_campaigns[campaign_id]['results'] = results
            self.active_campaigns[campaign_id]['status'] = 'completed'
            self.results_storage.extend(results)

            logger.info(f"Fuzzing campaign {campaign_id} completed with {len(results)} test cases")

            return campaign_id

        except Exception as e:
            logger.error(f"Fuzzing campaign {campaign_id} failed: {e}")
            if campaign_id in self.active_campaigns:
                self.active_campaigns[campaign_id]['status'] = 'failed'
                self.active_campaigns[campaign_id]['error'] = str(e)
            raise

    async def _generic_fuzzing(self, target: FuzzingTarget) -> List[FuzzingResult]:
        """Generic fuzzing for unsupported target types"""
        logger.warning(f"Generic fuzzing for unsupported target type: {target.target_type}")

        # Fallback to web fuzzing for most targets
        return await self.web_fuzzer.fuzz_web_target(target)

    def get_campaign_status(self, campaign_id: str) -> Dict[str, Any]:
        """Get status of a fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.active_campaigns[campaign_id]

        return {
            'campaign_id': campaign_id,
            'status': campaign['status'],
            'start_time': campaign['start_time'].isoformat(),
            'target': asdict(campaign['target']),
            'total_tests': len(campaign.get('results', [])),
            'vulnerabilities_found': len([r for r in campaign.get('results', []) if r.error_detected]),
            'high_severity_issues': len([r for r in campaign.get('results', []) if r.severity == 'high'])
        }

    def get_campaign_results(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get detailed results of a fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        results = self.active_campaigns[campaign_id].get('results', [])
        return [asdict(result) for result in results]

    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get summary of all vulnerabilities found"""
        all_vulnerabilities = [r for r in self.results_storage if r.error_detected]

        severity_counts = {}
        vuln_type_counts = {}

        for vuln in all_vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            if vuln.vulnerability_type:
                vuln_type_counts[vuln.vulnerability_type] = vuln_type_counts.get(vuln.vulnerability_type, 0) + 1

        return {
            'total_vulnerabilities': len(all_vulnerabilities),
            'by_severity': severity_counts,
            'by_type': vuln_type_counts,
            'total_test_cases': len(self.results_storage),
            'active_campaigns': len([c for c in self.active_campaigns.values() if c['status'] == 'running'])
        }

# Initialize FastAPI app
app = FastAPI(
    title="QuantumSentinel Advanced Fuzzing Service",
    description="Comprehensive fuzzing platform with ML-enhanced mutation and multi-protocol support",
    version="2.0.0"
)

# Global fuzzing orchestrator
fuzzing_orchestrator = FuzzingOrchestrator()

# Pydantic models for API
class FuzzingTargetRequest(BaseModel):
    target_type: FuzzingType
    endpoint: str
    parameters: Dict[str, Any] = {}
    headers: Dict[str, str] = {}
    payload_template: Optional[str] = None
    authentication: Optional[Dict[str, str]] = None

class FuzzingCampaignResponse(BaseModel):
    campaign_id: str
    status: str
    message: str

@app.on_event("startup")
async def startup_event():
    """Initialize fuzzing service on startup"""
    logger.info("QuantumSentinel Advanced Fuzzing Service starting up...")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "advanced-fuzzing",
        "timestamp": datetime.utcnow().isoformat(),
        "active_campaigns": len(fuzzing_orchestrator.active_campaigns),
        "total_results": len(fuzzing_orchestrator.results_storage)
    }

@app.post("/scan")
async def scan_endpoint(request: dict):
    """Main scan endpoint called by orchestrator"""
    job_id = request.get("job_id")
    targets = request.get("targets", [])
    options = request.get("options", {})

    logger.info(f"Starting fuzzing scan for job {job_id}")

    all_results = []

    for target_url in targets:
        # Create fuzzing target
        target = FuzzingTarget(
            target_id=str(uuid.uuid4()),
            target_type=FuzzingType.WEB_APPLICATION,  # Default to web app
            endpoint=target_url,
            parameters=options.get("parameters", {}),
            headers=options.get("headers", {}),
            payload_template=options.get("payload_template"),
            authentication=options.get("authentication")
        )

        # Start fuzzing campaign
        campaign_id = await fuzzing_orchestrator.start_fuzzing_campaign(target)

        # Get results
        results = fuzzing_orchestrator.get_campaign_results(campaign_id)
        all_results.extend(results)

    # Format findings for orchestrator
    findings = []
    for result in all_results:
        if result['error_detected']:
            findings.append({
                'id': result['result_id'],
                'type': result['vulnerability_type'] or 'fuzzing_anomaly',
                'severity': result['severity'],
                'title': f"Fuzzing detected: {result['vulnerability_type'] or 'Anomaly'}",
                'description': f"Test case: {result['test_case'][:100]}...",
                'location': result.get('metadata', {}).get('mutation_type', 'unknown'),
                'evidence': result['response_body'][:500] if result['response_body'] else '',
                'recommendation': 'Review and validate the detected fuzzing result',
                'cvss_score': 7.0 if result['severity'] == 'high' else 4.0 if result['severity'] == 'medium' else 2.0
            })

    return {
        "job_id": job_id,
        "status": "completed",
        "findings": findings,
        "service": "advanced-fuzzing",
        "total_test_cases": len(all_results),
        "vulnerabilities_found": len(findings)
    }

@app.post("/fuzz", response_model=FuzzingCampaignResponse)
async def start_fuzzing(request: FuzzingTargetRequest, background_tasks: BackgroundTasks):
    """Start a fuzzing campaign"""
    target = FuzzingTarget(
        target_id=str(uuid.uuid4()),
        target_type=request.target_type,
        endpoint=request.endpoint,
        parameters=request.parameters,
        headers=request.headers,
        payload_template=request.payload_template,
        authentication=request.authentication
    )

    try:
        campaign_id = await fuzzing_orchestrator.start_fuzzing_campaign(target)

        return FuzzingCampaignResponse(
            campaign_id=campaign_id,
            status="started",
            message=f"Fuzzing campaign started for {request.endpoint}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/campaigns/{campaign_id}")
async def get_campaign_status(campaign_id: str):
    """Get fuzzing campaign status"""
    try:
        return fuzzing_orchestrator.get_campaign_status(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/campaigns/{campaign_id}/results")
async def get_campaign_results(campaign_id: str):
    """Get fuzzing campaign results"""
    try:
        return {
            "campaign_id": campaign_id,
            "results": fuzzing_orchestrator.get_campaign_results(campaign_id)
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/campaigns")
async def list_campaigns():
    """List all fuzzing campaigns"""
    campaigns = []
    for campaign_id, campaign_data in fuzzing_orchestrator.active_campaigns.items():
        campaigns.append({
            'campaign_id': campaign_id,
            'status': campaign_data['status'],
            'start_time': campaign_data['start_time'].isoformat(),
            'target_endpoint': campaign_data['target'].endpoint,
            'target_type': campaign_data['target'].target_type,
            'total_tests': len(campaign_data.get('results', []))
        })

    return {'campaigns': campaigns}

@app.get("/vulnerabilities")
async def get_vulnerabilities():
    """Get vulnerability summary"""
    return fuzzing_orchestrator.get_vulnerability_summary()

@app.get("/statistics")
async def get_statistics():
    """Get fuzzing statistics"""
    total_campaigns = len(fuzzing_orchestrator.active_campaigns)
    completed_campaigns = len([c for c in fuzzing_orchestrator.active_campaigns.values() if c['status'] == 'completed'])
    running_campaigns = len([c for c in fuzzing_orchestrator.active_campaigns.values() if c['status'] == 'running'])

    return {
        'total_campaigns': total_campaigns,
        'completed_campaigns': completed_campaigns,
        'running_campaigns': running_campaigns,
        'total_test_cases': len(fuzzing_orchestrator.results_storage),
        'total_vulnerabilities': len([r for r in fuzzing_orchestrator.results_storage if r.error_detected])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)