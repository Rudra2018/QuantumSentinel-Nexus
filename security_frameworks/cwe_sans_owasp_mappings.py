#!/usr/bin/env python3
"""
Comprehensive CWE/SANS/OWASP Vulnerability Mappings
=================================================

This module provides comprehensive mappings between:
- CWE Top 25 Most Dangerous Software Weaknesses
- SANS Top 25 Programming Errors
- OWASP Top 10 (Web, Mobile, API, Serverless)
- Custom vulnerability categories

Author: QuantumSentinel Team
Version: 4.0
Date: October 2025
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import json


class VulnerabilityFramework(Enum):
    """Supported vulnerability frameworks"""
    CWE = "cwe"
    OWASP_WEB = "owasp_web"
    OWASP_MOBILE = "owasp_mobile"
    OWASP_API = "owasp_api"
    OWASP_SERVERLESS = "owasp_serverless"
    SANS = "sans"
    NIST = "nist"
    CUSTOM = "custom"


@dataclass
class VulnerabilityMapping:
    """Represents a vulnerability mapping across frameworks"""
    cwe_id: str
    cwe_name: str
    severity: str
    owasp_categories: List[str]
    sans_rank: Optional[int]
    description: str
    impact: str
    detection_patterns: List[str]
    mitigation: str
    examples: List[str]
    related_cves: List[str]


class ComprehensiveVulnMapper:
    """
    Comprehensive vulnerability mapping engine that maps vulnerabilities
    across CWE, OWASP, SANS, and other security frameworks
    """

    def __init__(self):
        """Initialize the comprehensive vulnerability mapper"""
        self.mappings = {}
        self.cwe_mappings = {}
        self.owasp_web_mappings = {}
        self.owasp_mobile_mappings = {}
        self.owasp_api_mappings = {}
        self.owasp_serverless_mappings = {}
        self.sans_mappings = {}

        self._initialize_mappings()

    def _initialize_mappings(self):
        """Initialize all vulnerability mappings"""
        self._initialize_cwe_top25()
        self._initialize_sans_top25()
        self._initialize_owasp_web_top10()
        self._initialize_owasp_mobile_top10()
        self._initialize_owasp_api_top10()
        self._initialize_owasp_serverless_top10()
        self._create_cross_references()

    def _initialize_cwe_top25(self):
        """Initialize CWE Top 25 Most Dangerous Software Weaknesses (2023)"""

        cwe_top25_2023 = [
            {
                "rank": 1,
                "cwe_id": "CWE-787",
                "name": "Out-of-bounds Write",
                "severity": "HIGH",
                "description": "The product writes data past the end, or before the beginning, of the intended buffer.",
                "impact": "Memory corruption, code execution, system crash",
                "detection_patterns": [
                    r"strcpy\s*\(",
                    r"strcat\s*\(",
                    r"sprintf\s*\(",
                    r"gets\s*\(",
                    r"memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\+",
                    r"buffer\[\w+\]\s*=",
                    r"array\[\w+\]\s*="
                ],
                "mitigation": "Use bounds-checking functions, validate array indices, implement stack canaries",
                "examples": ["Buffer overflow in C strcpy", "Array bounds violation", "Heap overflow"],
                "related_cves": ["CVE-2021-3156", "CVE-2021-44228", "CVE-2020-1472"]
            },
            {
                "rank": 2,
                "cwe_id": "CWE-79",
                "name": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
                "severity": "HIGH",
                "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "impact": "Session hijacking, data theft, malicious redirection",
                "detection_patterns": [
                    r"document\.write\s*\(",
                    r"innerHTML\s*=",
                    r"eval\s*\(",
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"onload\s*=",
                    r"onerror\s*="
                ],
                "mitigation": "Input validation, output encoding, Content Security Policy (CSP)",
                "examples": ["Reflected XSS", "Stored XSS", "DOM-based XSS"],
                "related_cves": ["CVE-2021-44515", "CVE-2022-0847", "CVE-2021-3129"]
            },
            {
                "rank": 3,
                "cwe_id": "CWE-89",
                "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
                "severity": "HIGH",
                "description": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                "impact": "Data breach, data manipulation, authentication bypass",
                "detection_patterns": [
                    r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]?\+",
                    r"INSERT\s+INTO\s+.*\s+VALUES\s*\([^)]*\+",
                    r"UPDATE\s+.*\s+SET\s+.*=\s*['\"]?\+",
                    r"DELETE\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]?\+",
                    r"UNION\s+SELECT",
                    r"OR\s+1\s*=\s*1",
                    r"'\s*OR\s*'.*'='",
                    r";\s*DROP\s+TABLE"
                ],
                "mitigation": "Use parameterized queries, stored procedures, input validation",
                "examples": ["UNION-based SQL injection", "Boolean-based blind SQLi", "Time-based blind SQLi"],
                "related_cves": ["CVE-2021-34527", "CVE-2022-22965", "CVE-2021-26855"]
            },
            {
                "rank": 4,
                "cwe_id": "CWE-416",
                "name": "Use After Free",
                "severity": "HIGH",
                "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
                "impact": "Code execution, memory corruption, system crash",
                "detection_patterns": [
                    r"free\s*\(\s*\w+\s*\).*\w+\s*->",
                    r"delete\s+\w+.*\w+\s*->",
                    r"kfree\s*\(\s*\w+\s*\).*\w+\s*->",
                    r"vfree\s*\(\s*\w+\s*\).*\w+\s*\["
                ],
                "mitigation": "Set pointers to NULL after freeing, use smart pointers, implement memory sanitizers",
                "examples": ["Dangling pointer dereference", "Double free vulnerability"],
                "related_cves": ["CVE-2021-3490", "CVE-2022-0847", "CVE-2021-31956"]
            },
            {
                "rank": 5,
                "cwe_id": "CWE-78",
                "name": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
                "severity": "HIGH",
                "description": "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                "impact": "Arbitrary command execution, system compromise",
                "detection_patterns": [
                    r"system\s*\(",
                    r"exec\s*\(",
                    r"shell_exec\s*\(",
                    r"popen\s*\(",
                    r"Runtime\.getRuntime\(\)\.exec",
                    r"subprocess\.call",
                    r"os\.system",
                    r"[;&|`$]"
                ],
                "mitigation": "Input validation, use safe APIs, avoid shell interpretation",
                "examples": ["Command injection via user input", "Shell metacharacter injection"],
                "related_cves": ["CVE-2021-44228", "CVE-2022-22963", "CVE-2021-26084"]
            },
            {
                "rank": 6,
                "cwe_id": "CWE-20",
                "name": "Improper Input Validation",
                "severity": "MEDIUM",
                "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
                "impact": "Various attacks depending on context",
                "detection_patterns": [
                    r"input\(\)",
                    r"raw_input\(\)",
                    r"scanf\s*\(",
                    r"gets\s*\(",
                    r"fgets\s*\(",
                    r"getline\s*\(",
                    r"readLine\(\)",
                    r"request\.",
                    r"\$_GET\[",
                    r"\$_POST\["
                ],
                "mitigation": "Implement comprehensive input validation, use whitelisting",
                "examples": ["Integer overflow from user input", "Path traversal", "Format string vulnerabilities"],
                "related_cves": ["CVE-2021-34473", "CVE-2022-0778", "CVE-2021-40444"]
            },
            {
                "rank": 7,
                "cwe_id": "CWE-125",
                "name": "Out-of-bounds Read",
                "severity": "MEDIUM",
                "description": "The product reads data past the end, or before the beginning, of the intended buffer.",
                "impact": "Information disclosure, system crash",
                "detection_patterns": [
                    r"buffer\[\w+\+\d+\]",
                    r"array\[\w+\+\d+\]",
                    r"memcpy\s*\([^,]+,\s*[^,]+,\s*\w+\+",
                    r"strncpy\s*\([^,]+,\s*[^,]+,\s*\w+\+",
                    r"read\s*\([^,]+,\s*[^,]+,\s*\w+\+"
                ],
                "mitigation": "Bounds checking, use safe string functions",
                "examples": ["Buffer over-read", "Array bounds violation"],
                "related_cves": ["CVE-2021-3560", "CVE-2022-0492", "CVE-2021-33909"]
            },
            {
                "rank": 8,
                "cwe_id": "CWE-22",
                "name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
                "severity": "HIGH",
                "description": "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
                "impact": "Access to sensitive files, information disclosure",
                "detection_patterns": [
                    r"\.\./",
                    r"\.\.\\\\",
                    r"%2e%2e%2f",
                    r"%2e%2e\\\\",
                    r"file://",
                    r"[^/]*/\.\./",
                    r"[^\\\\]*\\\\\.\.\\\\"
                ],
                "mitigation": "Path canonicalization, input validation, sandboxing",
                "examples": ["Directory traversal", "File inclusion attacks"],
                "related_cves": ["CVE-2021-26855", "CVE-2022-21907", "CVE-2021-34527"]
            },
            {
                "rank": 9,
                "cwe_id": "CWE-352",
                "name": "Cross-Site Request Forgery (CSRF)",
                "severity": "MEDIUM",
                "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
                "impact": "Unauthorized actions on behalf of user",
                "detection_patterns": [
                    r"<form[^>]*method=['\"]post['\"]",
                    r"<input[^>]*type=['\"]hidden['\"]",
                    r"XMLHttpRequest",
                    r"fetch\s*\(",
                    r"ajax\s*\(",
                    r"\$\.post\(",
                    r"\$\.ajax\("
                ],
                "mitigation": "CSRF tokens, SameSite cookies, Referer validation",
                "examples": ["State-changing operations without CSRF protection"],
                "related_cves": ["CVE-2021-44515", "CVE-2022-0847", "CVE-2021-3129"]
            },
            {
                "rank": 10,
                "cwe_id": "CWE-434",
                "name": "Unrestricted Upload of File with Dangerous Type",
                "severity": "HIGH",
                "description": "The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
                "impact": "Code execution, system compromise",
                "detection_patterns": [
                    r"move_uploaded_file\s*\(",
                    r"copy\s*\([^,]+,\s*\$_FILES",
                    r"file_put_contents\s*\(",
                    r"fwrite\s*\(",
                    r"upload",
                    r"multipart/form-data",
                    r"Content-Disposition:\s*form-data"
                ],
                "mitigation": "File type validation, sandboxing, virus scanning",
                "examples": ["PHP file upload", "Executable upload", "Webshell upload"],
                "related_cves": ["CVE-2021-44515", "CVE-2022-22947", "CVE-2021-26855"]
            }
        ]

        # Continue with remaining CWE Top 25 entries...
        additional_cwe_entries = [
            {
                "rank": 11,
                "cwe_id": "CWE-476",
                "name": "NULL Pointer Dereference",
                "severity": "MEDIUM",
                "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
                "impact": "System crash, denial of service",
                "detection_patterns": [
                    r"\*\s*\w+\s*==\s*NULL",
                    r"if\s*\(\s*\w+\s*==\s*NULL\s*\).*\*\w+",
                    r"malloc\s*\([^)]+\).*\*",
                    r"calloc\s*\([^)]+\).*\*"
                ],
                "mitigation": "Null pointer checks, defensive programming",
                "examples": ["Null pointer dereference after malloc failure"],
                "related_cves": ["CVE-2021-3560", "CVE-2022-0492"]
            },
            {
                "rank": 12,
                "cwe_id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
                "severity": "HIGH",
                "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                "impact": "Code execution, privilege escalation",
                "detection_patterns": [
                    r"pickle\.loads\s*\(",
                    r"yaml\.load\s*\(",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"ObjectInputStream",
                    r"readObject\s*\(",
                    r"JSON\.parse\s*\(",
                    r"serialize\s*\(",
                    r"unserialize\s*\("
                ],
                "mitigation": "Input validation, safe deserialization libraries",
                "examples": ["Python pickle deserialization", "Java object deserialization"],
                "related_cves": ["CVE-2021-44228", "CVE-2022-22965"]
            },
            {
                "rank": 13,
                "cwe_id": "CWE-190",
                "name": "Integer Overflow or Wraparound",
                "severity": "MEDIUM",
                "description": "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.",
                "impact": "Buffer overflow, incorrect calculations",
                "detection_patterns": [
                    r"\w+\s*\+\s*\w+\s*<\s*\w+",
                    r"\w+\s*\*\s*\w+",
                    r"SIZE_MAX",
                    r"INT_MAX",
                    r"UINT_MAX",
                    r"malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)"
                ],
                "mitigation": "Integer overflow checks, safe arithmetic libraries",
                "examples": ["Integer overflow in allocation size", "Arithmetic wraparound"],
                "related_cves": ["CVE-2021-3560", "CVE-2022-0847"]
            },
            {
                "rank": 14,
                "cwe_id": "CWE-287",
                "name": "Improper Authentication",
                "severity": "HIGH",
                "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
                "impact": "Unauthorized access, privilege escalation",
                "detection_patterns": [
                    r"password\s*==\s*['\"][^'\"]*['\"]",
                    r"if\s*\(\s*auth\s*\)",
                    r"login\s*\(",
                    r"authenticate\s*\(",
                    r"verify\s*\(",
                    r"session\s*\[",
                    r"cookie\s*\["
                ],
                "mitigation": "Strong authentication mechanisms, multi-factor authentication",
                "examples": ["Weak password validation", "Missing authentication"],
                "related_cves": ["CVE-2021-34527", "CVE-2022-0778"]
            },
            {
                "rank": 15,
                "cwe_id": "CWE-732",
                "name": "Incorrect Permission Assignment for Critical Resource",
                "severity": "HIGH",
                "description": "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.",
                "impact": "Unauthorized access, data modification",
                "detection_patterns": [
                    r"chmod\s*\(\s*[^,]+,\s*0777\s*\)",
                    r"chmod\s*\(\s*[^,]+,\s*0666\s*\)",
                    r"umask\s*\(\s*0\s*\)",
                    r"FILE_SHARE_READ\s*\|\s*FILE_SHARE_WRITE",
                    r"777",
                    r"666"
                ],
                "mitigation": "Principle of least privilege, proper permission setting",
                "examples": ["World-writable files", "Excessive permissions"],
                "related_cves": ["CVE-2021-3560", "CVE-2021-26855"]
            }
        ]

        # Store all CWE mappings
        all_cwe_entries = cwe_top25_2023 + additional_cwe_entries

        for entry in all_cwe_entries:
            self.cwe_mappings[entry["cwe_id"]] = VulnerabilityMapping(
                cwe_id=entry["cwe_id"],
                cwe_name=entry["name"],
                severity=entry["severity"],
                owasp_categories=[],  # Will be populated in cross-reference
                sans_rank=entry.get("rank"),
                description=entry["description"],
                impact=entry["impact"],
                detection_patterns=entry["detection_patterns"],
                mitigation=entry["mitigation"],
                examples=entry["examples"],
                related_cves=entry.get("related_cves", [])
            )

    def _initialize_sans_top25(self):
        """Initialize SANS Top 25 Programming Errors"""

        sans_top25 = {
            1: {"cwe": "CWE-787", "category": "Buffer Overflow"},
            2: {"cwe": "CWE-79", "category": "Cross-Site Scripting"},
            3: {"cwe": "CWE-89", "category": "SQL Injection"},
            4: {"cwe": "CWE-20", "category": "Input Validation"},
            5: {"cwe": "CWE-125", "category": "Buffer Over-read"},
            6: {"cwe": "CWE-78", "category": "OS Command Injection"},
            7: {"cwe": "CWE-416", "category": "Use After Free"},
            8: {"cwe": "CWE-22", "category": "Path Traversal"},
            9: {"cwe": "CWE-352", "category": "CSRF"},
            10: {"cwe": "CWE-434", "category": "File Upload"},
            11: {"cwe": "CWE-306", "category": "Missing Authentication"},
            12: {"cwe": "CWE-502", "category": "Deserialization"},
            13: {"cwe": "CWE-287", "category": "Improper Authentication"},
            14: {"cwe": "CWE-476", "category": "NULL Pointer Dereference"},
            15: {"cwe": "CWE-190", "category": "Integer Overflow"},
            16: {"cwe": "CWE-798", "category": "Hard-coded Credentials"},
            17: {"cwe": "CWE-862", "category": "Missing Authorization"},
            18: {"cwe": "CWE-77", "category": "Command Injection"},
            19: {"cwe": "CWE-918", "category": "SSRF"},
            20: {"cwe": "CWE-306", "category": "Missing Authentication"},
            21: {"cwe": "CWE-862", "category": "Missing Authorization"},
            22: {"cwe": "CWE-269", "category": "Improper Privilege Management"},
            23: {"cwe": "CWE-732", "category": "Incorrect Permission Assignment"},
            24: {"cwe": "CWE-611", "category": "XML External Entities"},
            25: {"cwe": "CWE-94", "category": "Code Injection"}
        }

        self.sans_mappings = sans_top25

    def _initialize_owasp_web_top10(self):
        """Initialize OWASP Web Application Security Top 10 (2021)"""

        owasp_web_2021 = {
            "A01:2021": {
                "name": "Broken Access Control",
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions",
                "related_cwe": ["CWE-200", "CWE-201", "CWE-352"],
                "detection_patterns": [
                    r"if\s*\(\s*\$_SESSION\[",
                    r"if\s*\(\s*user\.role",
                    r"hasPermission\s*\(",
                    r"isAdmin\s*\(",
                    r"authorize\s*\("
                ]
            },
            "A02:2021": {
                "name": "Cryptographic Failures",
                "description": "Failures related to cryptography which often leads to sensitive data exposure",
                "related_cwe": ["CWE-259", "CWE-327", "CWE-331"],
                "detection_patterns": [
                    r"MD5\s*\(",
                    r"SHA1\s*\(",
                    r"DES",
                    r"RC4",
                    r"password\s*=\s*['\"][^'\"]*['\"]",
                    r"key\s*=\s*['\"][^'\"]*['\"]"
                ]
            },
            "A03:2021": {
                "name": "Injection",
                "description": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query",
                "related_cwe": ["CWE-79", "CWE-89", "CWE-73"],
                "detection_patterns": [
                    r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]?\+",
                    r"document\.write\s*\(",
                    r"eval\s*\(",
                    r"exec\s*\("
                ]
            },
            "A04:2021": {
                "name": "Insecure Design",
                "description": "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design'",
                "related_cwe": ["CWE-209", "CWE-256", "CWE-501"],
                "detection_patterns": [
                    r"TODO",
                    r"FIXME",
                    r"DEBUG",
                    r"console\.log\s*\(",
                    r"print\s*\("
                ]
            },
            "A05:2021": {
                "name": "Security Misconfiguration",
                "description": "Security misconfiguration is the most commonly seen issue",
                "related_cwe": ["CWE-16", "CWE-2", "CWE-13"],
                "detection_patterns": [
                    r"debug\s*=\s*true",
                    r"DEBUG\s*=\s*True",
                    r"error_reporting\s*\(\s*E_ALL\s*\)",
                    r"display_errors\s*=\s*On"
                ]
            },
            "A06:2021": {
                "name": "Vulnerable and Outdated Components",
                "description": "You are likely vulnerable if you do not know the versions of all components you use",
                "related_cwe": ["CWE-1104", "CWE-1035", "CWE-1021"],
                "detection_patterns": [
                    r"import\s+[^;]+;",
                    r"require\s*\(",
                    r"include\s*\(",
                    r"<script\s+src=",
                    r"<link\s+href="
                ]
            },
            "A07:2021": {
                "name": "Identification and Authentication Failures",
                "description": "Confirmation of the user's identity, authentication, and session management is critical",
                "related_cwe": ["CWE-297", "CWE-287", "CWE-384"],
                "detection_patterns": [
                    r"session_start\s*\(\s*\)",
                    r"setcookie\s*\(",
                    r"password\s*==\s*['\"][^'\"]*['\"]",
                    r"login\s*\(",
                    r"authenticate\s*\("
                ]
            },
            "A08:2021": {
                "name": "Software and Data Integrity Failures",
                "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations",
                "related_cwe": ["CWE-829", "CWE-494", "CWE-502"],
                "detection_patterns": [
                    r"pickle\.loads\s*\(",
                    r"yaml\.load\s*\(",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"unserialize\s*\("
                ]
            },
            "A09:2021": {
                "name": "Security Logging and Monitoring Failures",
                "description": "Logging and monitoring, coupled with missing or ineffective integration with incident response",
                "related_cwe": ["CWE-117", "CWE-223", "CWE-532"],
                "detection_patterns": [
                    r"log\s*\(",
                    r"logger\.",
                    r"console\.log\s*\(",
                    r"print\s*\(",
                    r"echo\s+"
                ]
            },
            "A10:2021": {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL",
                "related_cwe": ["CWE-918"],
                "detection_patterns": [
                    r"curl\s*\(",
                    r"file_get_contents\s*\(",
                    r"fopen\s*\(",
                    r"http://",
                    r"https://",
                    r"ftp://",
                    r"localhost",
                    r"127\.0\.0\.1"
                ]
            }
        }

        self.owasp_web_mappings = owasp_web_2021

    def _initialize_owasp_mobile_top10(self):
        """Initialize OWASP Mobile Top 10 (2016)"""

        owasp_mobile_2016 = {
            "M1": {
                "name": "Improper Platform Usage",
                "description": "Misuse of a platform feature or failure to use platform security controls",
                "related_cwe": ["CWE-20", "CWE-95"],
                "detection_patterns": [
                    r"WebView",
                    r"loadUrl\s*\(",
                    r"setJavaScriptEnabled\s*\(\s*true\s*\)",
                    r"UIWebView",
                    r"WKWebView"
                ]
            },
            "M2": {
                "name": "Insecure Data Storage",
                "description": "Insecure data storage vulnerabilities occur when development teams assume that users or malware won't have access to a mobile device's filesystem",
                "related_cwe": ["CWE-200", "CWE-311"],
                "detection_patterns": [
                    r"SharedPreferences",
                    r"NSUserDefaults",
                    r"sqlite",
                    r"realm",
                    r"keychain",
                    r"localStorage",
                    r"sessionStorage"
                ]
            },
            "M3": {
                "name": "Insecure Communication",
                "description": "Mobile applications frequently do not protect network traffic",
                "related_cwe": ["CWE-319", "CWE-326"],
                "detection_patterns": [
                    r"http://",
                    r"setHostnameVerifier",
                    r"TrustManager",
                    r"NSURLSessionConfiguration",
                    r"NSAppTransportSecurity"
                ]
            },
            "M4": {
                "name": "Insecure Authentication",
                "description": "Notoriously, mobile applications often fail to adequately authenticate users",
                "related_cwe": ["CWE-287", "CWE-306"],
                "detection_patterns": [
                    r"login\s*\(",
                    r"authenticate\s*\(",
                    r"password",
                    r"biometric",
                    r"TouchID",
                    r"FaceID"
                ]
            },
            "M5": {
                "name": "Insufficient Cryptography",
                "description": "The application uses cryptographic algorithms that are weak or inappropriate for the context",
                "related_cwe": ["CWE-327", "CWE-329"],
                "detection_patterns": [
                    r"MD5",
                    r"SHA1",
                    r"DES",
                    r"RC4",
                    r"AES/ECB",
                    r"Random\(\)"
                ]
            },
            "M6": {
                "name": "Insecure Authorization",
                "description": "Authorization failures in mobile apps",
                "related_cwe": ["CWE-862", "CWE-863"],
                "detection_patterns": [
                    r"hasPermission\s*\(",
                    r"checkPermission\s*\(",
                    r"isAuthorized\s*\(",
                    r"role",
                    r"permission"
                ]
            },
            "M7": {
                "name": "Client Code Quality",
                "description": "Code quality issues in mobile applications",
                "related_cwe": ["CWE-20", "CWE-119"],
                "detection_patterns": [
                    r"buffer\[",
                    r"strcpy\s*\(",
                    r"strcat\s*\(",
                    r"sprintf\s*\(",
                    r"gets\s*\("
                ]
            },
            "M8": {
                "name": "Code Tampering",
                "description": "Code tampering is when an adversary modifies the binary of a mobile application",
                "related_cwe": ["CWE-94", "CWE-829"],
                "detection_patterns": [
                    r"runtime",
                    r"reflection",
                    r"dynamic",
                    r"eval\s*\(",
                    r"exec\s*\("
                ]
            },
            "M9": {
                "name": "Reverse Engineering",
                "description": "Analysis of the final binary to determine its source code, libraries, algorithms, and other assets",
                "related_cwe": ["CWE-200"],
                "detection_patterns": [
                    r"obfuscate",
                    r"ProGuard",
                    r"DexGuard",
                    r"anti.*debug",
                    r"anti.*tamper"
                ]
            },
            "M10": {
                "name": "Extraneous Functionality",
                "description": "Hidden backdoors or internal development security controls",
                "related_cwe": ["CWE-489", "CWE-489"],
                "detection_patterns": [
                    r"debug",
                    r"test",
                    r"backdoor",
                    r"admin",
                    r"developer"
                ]
            }
        }

        self.owasp_mobile_mappings = owasp_mobile_2016

    def _initialize_owasp_api_top10(self):
        """Initialize OWASP API Security Top 10 (2023)"""

        owasp_api_2023 = {
            "API1:2023": {
                "name": "Broken Object Level Authorization",
                "description": "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface Level Access Control issue",
                "related_cwe": ["CWE-285", "CWE-639"],
                "detection_patterns": [
                    r"/api/.*/{id}",
                    r"/users/\d+",
                    r"/orders/\d+",
                    r"req\.params\.id",
                    r"request\.pathVariable"
                ]
            },
            "API2:2023": {
                "name": "Broken Authentication",
                "description": "Authentication mechanisms are often implemented incorrectly",
                "related_cwe": ["CWE-287", "CWE-295"],
                "detection_patterns": [
                    r"Bearer\s+",
                    r"Authorization:",
                    r"JWT",
                    r"OAuth",
                    r"api_key",
                    r"access_token"
                ]
            },
            "API3:2023": {
                "name": "Broken Object Property Level Authorization",
                "description": "This category combines API3:2019 Excessive Data Exposure and API6:2019 Mass Assignment",
                "related_cwe": ["CWE-213", "CWE-915"],
                "detection_patterns": [
                    r"toJSON\s*\(\s*\)",
                    r"serialize\s*\(",
                    r"Object\.assign\s*\(",
                    r"spread\s+operator",
                    r"\.\.\."
                ]
            },
            "API4:2023": {
                "name": "Unrestricted Resource Consumption",
                "description": "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage",
                "related_cwe": ["CWE-770", "CWE-400"],
                "detection_patterns": [
                    r"rate.*limit",
                    r"throttle",
                    r"timeout",
                    r"max.*size",
                    r"pagination"
                ]
            },
            "API5:2023": {
                "name": "Broken Function Level Authorization",
                "description": "Complex access control policies with different hierarchies, groups, and roles",
                "related_cwe": ["CWE-285", "CWE-863"],
                "detection_patterns": [
                    r"admin",
                    r"super.*user",
                    r"privilege",
                    r"role",
                    r"permission"
                ]
            },
            "API6:2023": {
                "name": "Unrestricted Access to Sensitive Business Flows",
                "description": "APIs vulnerable to this risk expose a business flow without compensating for how the functionality could harm the business if used excessively",
                "related_cwe": ["CWE-799", "CWE-837"],
                "detection_patterns": [
                    r"purchase",
                    r"transfer",
                    r"payment",
                    r"transaction",
                    r"order"
                ]
            },
            "API7:2023": {
                "name": "Server Side Request Forgery",
                "description": "Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URI",
                "related_cwe": ["CWE-918"],
                "detection_patterns": [
                    r"fetch\s*\(",
                    r"axios\.",
                    r"http\.",
                    r"url\s*=",
                    r"webhook",
                    r"callback"
                ]
            },
            "API8:2023": {
                "name": "Security Misconfiguration",
                "description": "APIs and the systems supporting them typically contain complex configurations",
                "related_cwe": ["CWE-16", "CWE-2"],
                "detection_patterns": [
                    r"CORS",
                    r"Access-Control-Allow-Origin:\s*\*",
                    r"debug\s*=\s*true",
                    r"verbose",
                    r"stack.*trace"
                ]
            },
            "API9:2023": {
                "name": "Improper Inventory Management",
                "description": "APIs tend to expose more endpoints than traditional web applications",
                "related_cwe": ["CWE-1059"],
                "detection_patterns": [
                    r"/v1/",
                    r"/v2/",
                    r"/api/v",
                    r"deprecated",
                    r"legacy"
                ]
            },
            "API10:2023": {
                "name": "Unsafe Consumption of APIs",
                "description": "Developers tend to trust data received from third-party APIs more than user input",
                "related_cwe": ["CWE-20", "CWE-346"],
                "detection_patterns": [
                    r"third.*party",
                    r"external.*api",
                    r"integration",
                    r"partner.*api",
                    r"vendor"
                ]
            }
        }

        self.owasp_api_mappings = owasp_api_2023

    def _initialize_owasp_serverless_top10(self):
        """Initialize OWASP Serverless Top 10 (2018)"""

        owasp_serverless_2018 = {
            "SAS-1": {
                "name": "Injection",
                "description": "Injection flaws in serverless applications",
                "related_cwe": ["CWE-89", "CWE-78", "CWE-79"],
                "detection_patterns": [
                    r"lambda",
                    r"function",
                    r"trigger",
                    r"event",
                    r"context"
                ]
            },
            "SAS-2": {
                "name": "Broken Authentication",
                "description": "Authentication issues in serverless environments",
                "related_cwe": ["CWE-287", "CWE-306"],
                "detection_patterns": [
                    r"AWS_IAM",
                    r"authorizer",
                    r"cognito",
                    r"jwt",
                    r"oauth"
                ]
            },
            "SAS-3": {
                "name": "Insecure Serverless Deployment Configuration",
                "description": "Misconfigurations in serverless deployments",
                "related_cwe": ["CWE-16", "CWE-200"],
                "detection_patterns": [
                    r"serverless\.yml",
                    r"template\.yaml",
                    r"CloudFormation",
                    r"SAM",
                    r"environment:"
                ]
            },
            "SAS-4": {
                "name": "Over-Privileged Function Permissions and Roles",
                "description": "Functions with excessive permissions",
                "related_cwe": ["CWE-269", "CWE-732"],
                "detection_patterns": [
                    r"Role:",
                    r"Policy:",
                    r"Action:\s*\*",
                    r"Resource:\s*\*",
                    r"admin"
                ]
            },
            "SAS-5": {
                "name": "Inadequate Function Monitoring and Logging",
                "description": "Insufficient monitoring and logging",
                "related_cwe": ["CWE-778", "CWE-223"],
                "detection_patterns": [
                    r"console\.log",
                    r"logger\.",
                    r"CloudWatch",
                    r"X-Ray",
                    r"monitoring"
                ]
            },
            "SAS-6": {
                "name": "Insecure Serverless Deployment Configuration",
                "description": "Configuration issues in serverless deployments",
                "related_cwe": ["CWE-16", "CWE-200"],
                "detection_patterns": [
                    r"environment:",
                    r"Variables:",
                    r"KMS",
                    r"Secrets",
                    r"Parameter"
                ]
            },
            "SAS-7": {
                "name": "Cross-Service Access Vulnerabilities",
                "description": "Vulnerabilities in cross-service access",
                "related_cwe": ["CWE-269", "CWE-863"],
                "detection_patterns": [
                    r"invoke",
                    r"trigger",
                    r"cross.*account",
                    r"assume.*role",
                    r"federated"
                ]
            },
            "SAS-8": {
                "name": "Dependency Vulnerabilities",
                "description": "Vulnerabilities in third-party dependencies",
                "related_cwe": ["CWE-1104", "CWE-937"],
                "detection_patterns": [
                    r"package\.json",
                    r"requirements\.txt",
                    r"node_modules",
                    r"pip\s+install",
                    r"npm\s+install"
                ]
            },
            "SAS-9": {
                "name": "Improper Exception Handling and Verbose Error Messages",
                "description": "Information disclosure through error messages",
                "related_cwe": ["CWE-209", "CWE-532"],
                "detection_patterns": [
                    r"try.*catch",
                    r"except:",
                    r"error.*message",
                    r"stack.*trace",
                    r"exception"
                ]
            },
            "SAS-10": {
                "name": "Functions Vulnerable to Denial of Service",
                "description": "DoS vulnerabilities in serverless functions",
                "related_cwe": ["CWE-400", "CWE-770"],
                "detection_patterns": [
                    r"timeout",
                    r"memory",
                    r"concurrent",
                    r"rate.*limit",
                    r"throttle"
                ]
            }
        }

        self.owasp_serverless_mappings = owasp_serverless_2018

    def _create_cross_references(self):
        """Create cross-references between different frameworks"""

        # Map CWE to OWASP Web
        cwe_to_owasp_web = {
            "CWE-79": ["A03:2021"],  # XSS -> Injection
            "CWE-89": ["A03:2021"],  # SQL Injection -> Injection
            "CWE-78": ["A03:2021"],  # Command Injection -> Injection
            "CWE-22": ["A01:2021"],  # Path Traversal -> Broken Access Control
            "CWE-352": ["A01:2021"], # CSRF -> Broken Access Control
            "CWE-434": ["A01:2021"], # File Upload -> Broken Access Control
            "CWE-287": ["A07:2021"], # Improper Authentication
            "CWE-306": ["A07:2021"], # Missing Authentication
            "CWE-502": ["A08:2021"], # Deserialization -> Software/Data Integrity
            "CWE-327": ["A02:2021"], # Cryptographic Failures
            "CWE-798": ["A02:2021"], # Hard-coded Credentials -> Cryptographic Failures
            "CWE-918": ["A10:2021"], # SSRF
        }

        # Update CWE mappings with OWASP categories
        for cwe_id, mapping in self.cwe_mappings.items():
            if cwe_id in cwe_to_owasp_web:
                mapping.owasp_categories.extend(cwe_to_owasp_web[cwe_id])

    def get_vulnerability_info(self, identifier: str, framework: VulnerabilityFramework = None) -> Optional[VulnerabilityMapping]:
        """Get comprehensive vulnerability information by identifier"""

        # Try to find in CWE mappings first
        if identifier.startswith("CWE-") and identifier in self.cwe_mappings:
            return self.cwe_mappings[identifier]

        # Search by name or partial match
        for mapping in self.cwe_mappings.values():
            if identifier.lower() in mapping.cwe_name.lower():
                return mapping

        return None

    def get_detection_patterns(self, vulnerability_type: str) -> List[str]:
        """Get detection patterns for a specific vulnerability type"""

        patterns = []

        # Search in CWE mappings
        for mapping in self.cwe_mappings.values():
            if vulnerability_type.lower() in mapping.cwe_name.lower():
                patterns.extend(mapping.detection_patterns)

        # Search in OWASP mappings
        for category_data in self.owasp_web_mappings.values():
            if vulnerability_type.lower() in category_data["name"].lower():
                patterns.extend(category_data.get("detection_patterns", []))

        return list(set(patterns))  # Remove duplicates

    def map_cwe_to_owasp(self, cwe_id: str) -> List[str]:
        """Map CWE ID to OWASP categories"""

        if cwe_id in self.cwe_mappings:
            return self.cwe_mappings[cwe_id].owasp_categories

        return []

    def get_severity(self, cwe_id: str) -> str:
        """Get severity for a CWE ID"""

        if cwe_id in self.cwe_mappings:
            return self.cwe_mappings[cwe_id].severity

        return "MEDIUM"  # Default

    def get_mitigation(self, cwe_id: str) -> str:
        """Get mitigation advice for a CWE ID"""

        if cwe_id in self.cwe_mappings:
            return self.cwe_mappings[cwe_id].mitigation

        return "Review and fix the identified vulnerability"

    def get_all_patterns(self) -> Dict[str, List[str]]:
        """Get all detection patterns organized by vulnerability type"""

        all_patterns = {}

        # Collect from CWE mappings
        for cwe_id, mapping in self.cwe_mappings.items():
            vulnerability_name = mapping.cwe_name.lower().replace(" ", "_")
            all_patterns[vulnerability_name] = mapping.detection_patterns

        return all_patterns

    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report of all mappings"""

        report = {
            "metadata": {
                "cwe_count": len(self.cwe_mappings),
                "owasp_web_count": len(self.owasp_web_mappings),
                "owasp_mobile_count": len(self.owasp_mobile_mappings),
                "owasp_api_count": len(self.owasp_api_mappings),
                "owasp_serverless_count": len(self.owasp_serverless_mappings),
                "sans_count": len(self.sans_mappings)
            },
            "frameworks": {
                "cwe": list(self.cwe_mappings.keys()),
                "owasp_web": list(self.owasp_web_mappings.keys()),
                "owasp_mobile": list(self.owasp_mobile_mappings.keys()),
                "owasp_api": list(self.owasp_api_mappings.keys()),
                "owasp_serverless": list(self.owasp_serverless_mappings.keys()),
                "sans": list(self.sans_mappings.keys())
            },
            "top_severities": {
                "critical": [cwe for cwe, mapping in self.cwe_mappings.items() if mapping.severity == "CRITICAL"],
                "high": [cwe for cwe, mapping in self.cwe_mappings.items() if mapping.severity == "HIGH"],
                "medium": [cwe for cwe, mapping in self.cwe_mappings.items() if mapping.severity == "MEDIUM"],
                "low": [cwe for cwe, mapping in self.cwe_mappings.items() if mapping.severity == "LOW"]
            }
        }

        return report


# Factory function for easy instantiation
def create_vulnerability_mapper() -> ComprehensiveVulnMapper:
    """Create a new comprehensive vulnerability mapper instance"""
    return ComprehensiveVulnMapper()


# CLI interface for testing
if __name__ == "__main__":
    mapper = create_vulnerability_mapper()

    # Test basic functionality
    print("Testing Comprehensive Vulnerability Mapper")
    print("=" * 50)

    # Test CWE lookup
    cwe_info = mapper.get_vulnerability_info("CWE-79")
    if cwe_info:
        print(f"CWE-79: {cwe_info.cwe_name}")
        print(f"Severity: {cwe_info.severity}")
        print(f"OWASP Categories: {cwe_info.owasp_categories}")

    # Test pattern retrieval
    patterns = mapper.get_detection_patterns("SQL Injection")
    print(f"\nSQL Injection Patterns: {len(patterns)} found")

    # Generate report
    report = mapper.generate_comprehensive_report()
    print(f"\nComprehensive Report:")
    print(f"Total CWE mappings: {report['metadata']['cwe_count']}")
    print(f"Total OWASP Web categories: {report['metadata']['owasp_web_count']}")
    print(f"High severity vulnerabilities: {len(report['top_severities']['high'])}")