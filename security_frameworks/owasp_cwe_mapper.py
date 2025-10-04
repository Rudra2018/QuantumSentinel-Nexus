#!/usr/bin/env python3
"""
🛡️ QuantumSentinel OWASP Top 10 2021 & CWE Comprehensive Mapping System
Advanced security framework mapping for vulnerability classification and compliance
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger("QuantumSentinel.OWASPCWEMapper")

class SeverityLevel(Enum):
    """Security severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class CWEEntry:
    """Common Weakness Enumeration entry"""
    cwe_id: str
    name: str
    description: str
    weakness_type: str
    likelihood: str
    impact: str
    detection_methods: List[str]
    prevention_methods: List[str]
    example_languages: List[str]
    related_attack_patterns: List[str]

@dataclass
class OWASPCategory:
    """OWASP Top 10 2021 category"""
    category_id: str
    name: str
    description: str
    impact: str
    prevalence: str
    detectability: str
    technical_impact: str
    business_impact: str
    prevention_strategies: List[str]
    testing_methods: List[str]
    example_scenarios: List[str]
    mapped_cwes: List[str]

@dataclass
class VulnerabilityMapping:
    """Complete vulnerability mapping"""
    vulnerability_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: float
    cwe_id: str
    owasp_category: str
    cvss_score: Optional[float] = None
    remediation_effort: Optional[str] = None
    business_risk: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None

class OWASPCWEMapper:
    """Comprehensive OWASP Top 10 2021 and CWE mapping system"""

    def __init__(self):
        self.owasp_categories = self._initialize_owasp_2021()
        self.cwe_database = self._initialize_cwe_database()
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()

    def _initialize_owasp_2021(self) -> Dict[str, OWASPCategory]:
        """Initialize OWASP Top 10 2021 categories"""
        return {
            "A01_2021": OWASPCategory(
                category_id="A01_2021",
                name="Broken Access Control",
                description="Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
                impact="HIGH",
                prevalence="Common",
                detectability="Average",
                technical_impact="HIGH",
                business_impact="HIGH",
                prevention_strategies=[
                    "Implement access control mechanisms with deny by default",
                    "Use centralized access control mechanisms",
                    "Implement proper session management",
                    "Apply principle of least privilege",
                    "Disable web server directory listing",
                    "Log access control failures and alert administrators"
                ],
                testing_methods=[
                    "Manual code review",
                    "Automated security testing",
                    "Penetration testing",
                    "Authentication bypass testing",
                    "Privilege escalation testing"
                ],
                example_scenarios=[
                    "URL manipulation to access unauthorized resources",
                    "Elevation of privilege attacks",
                    "Metadata manipulation",
                    "Force browsing to authenticated pages"
                ],
                mapped_cwes=["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"]
            ),
            "A02_2021": OWASPCategory(
                category_id="A02_2021",
                name="Cryptographic Failures",
                description="Failures related to cryptography which often leads to exposure of sensitive data. Previously known as Sensitive Data Exposure, which was more of a broad symptom rather than a root cause.",
                impact="HIGH",
                prevalence="Common",
                detectability="Difficult",
                technical_impact="HIGH",
                business_impact="HIGH",
                prevention_strategies=[
                    "Classify data and apply controls according to classification",
                    "Don't store sensitive data unnecessarily",
                    "Encrypt all sensitive data at rest",
                    "Ensure up-to-date and strong standard algorithms",
                    "Use proper key management",
                    "Encrypt all data in transit with secure protocols"
                ],
                testing_methods=[
                    "Code review for cryptographic implementations",
                    "Configuration review",
                    "Network traffic analysis",
                    "Data encryption verification",
                    "Key management assessment"
                ],
                example_scenarios=[
                    "Transmission of sensitive data in clear text",
                    "Use of old or weak cryptographic algorithms",
                    "Default crypto keys or weak crypto keys",
                    "Improper certificate validation"
                ],
                mapped_cwes=["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"]
            ),
            "A03_2021": OWASPCategory(
                category_id="A03_2021",
                name="Injection",
                description="An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application, or when hostile data is used within Object-Relational Mapping (ORM) search parameters.",
                impact="HIGH",
                prevalence="Common",
                detectability="Easy",
                technical_impact="HIGH",
                business_impact="HIGH",
                prevention_strategies=[
                    "Use safe APIs which avoid interpreter use entirely",
                    "Use positive server-side input validation",
                    "Escape special characters using output encoding",
                    "Use LIMIT and other SQL controls within queries",
                    "Use parameterized queries, stored procedures, or ORMs"
                ],
                testing_methods=[
                    "Static code analysis",
                    "Dynamic testing with injection payloads",
                    "Manual code review",
                    "Automated vulnerability scanning",
                    "Penetration testing"
                ],
                example_scenarios=[
                    "SQL injection in database queries",
                    "NoSQL injection in database queries",
                    "OS command injection",
                    "LDAP injection"
                ],
                mapped_cwes=["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"]
            ),
            "A04_2021": OWASPCategory(
                category_id="A04_2021",
                name="Insecure Design",
                description="Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. One of the factors that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed.",
                impact="HIGH",
                prevalence="Widespread",
                detectability="Difficult",
                technical_impact="MEDIUM",
                business_impact="HIGH",
                prevention_strategies=[
                    "Establish secure development lifecycle",
                    "Establish secure design pattern library",
                    "Use threat modeling for authentication, access control, and business logic",
                    "Integrate security language and controls into user stories",
                    "Write unit and integration tests to validate critical flows"
                ],
                testing_methods=[
                    "Architecture review",
                    "Threat modeling",
                    "Design review",
                    "Security requirements verification",
                    "Business logic testing"
                ],
                example_scenarios=[
                    "Missing business logic validation",
                    "Insecure direct object references",
                    "Missing rate limiting",
                    "Workflow bypasses"
                ],
                mapped_cwes=["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"]
            ),
            "A05_2021": OWASPCategory(
                category_id="A05_2021",
                name="Security Misconfiguration",
                description="The application might be vulnerable if it has any of the following: Missing appropriate security hardening across any part of the application stack, or improperly configured permissions on cloud services.",
                impact="MEDIUM",
                prevalence="Common",
                detectability="Easy",
                technical_impact="MEDIUM",
                business_impact="MEDIUM",
                prevention_strategies=[
                    "Implement repeatable hardening process",
                    "Use minimal platform without unnecessary features",
                    "Review and update configurations regularly",
                    "Use automated process for configuration verification",
                    "Use segmented application architecture"
                ],
                testing_methods=[
                    "Configuration scanning",
                    "Security configuration review",
                    "Automated compliance checking",
                    "Infrastructure as code scanning",
                    "Cloud security posture management"
                ],
                example_scenarios=[
                    "Default accounts and passwords",
                    "Directory listing enabled",
                    "Unnecessary features enabled",
                    "Detailed error messages to users"
                ],
                mapped_cwes=["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"]
            ),
            "A06_2021": OWASPCategory(
                category_id="A06_2021",
                name="Vulnerable and Outdated Components",
                description="You are likely vulnerable if you do not know the versions of all components you use, including nested dependencies, if the software is vulnerable, unsupported, or out of date.",
                impact="MEDIUM",
                prevalence="Widespread",
                detectability="Average",
                technical_impact="MEDIUM",
                business_impact="MEDIUM",
                prevention_strategies=[
                    "Remove unused dependencies and features",
                    "Continuously inventory component versions",
                    "Monitor security vulnerabilities in components",
                    "Obtain components from official sources",
                    "Use software composition analysis tools"
                ],
                testing_methods=[
                    "Software composition analysis",
                    "Dependency scanning",
                    "Version auditing",
                    "Vulnerability database checking",
                    "License compliance checking"
                ],
                example_scenarios=[
                    "Components with known vulnerabilities",
                    "Outdated or unsupported software",
                    "Failure to scan for vulnerabilities",
                    "Insecure component configuration"
                ],
                mapped_cwes=["CWE-1035", "CWE-1104"]
            ),
            "A07_2021": OWASPCategory(
                category_id="A07_2021",
                name="Identification and Authentication Failures",
                description="Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application permits automated attacks.",
                impact="HIGH",
                prevalence="Common",
                detectability="Average",
                technical_impact="HIGH",
                business_impact="HIGH",
                prevention_strategies=[
                    "Implement multi-factor authentication",
                    "Do not ship with default credentials",
                    "Implement weak password checks",
                    "Implement proper session management",
                    "Use server-side secure session manager"
                ],
                testing_methods=[
                    "Authentication testing",
                    "Session management testing",
                    "Password policy verification",
                    "Multi-factor authentication testing",
                    "Account lockout testing"
                ],
                example_scenarios=[
                    "Credential stuffing attacks",
                    "Brute force attacks",
                    "Default passwords",
                    "Weak password recovery"
                ],
                mapped_cwes=["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"]
            ),
            "A08_2021": OWASPCategory(
                category_id="A08_2021",
                name="Software and Data Integrity Failures",
                description="Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes software updates, critical data, and CI/CD pipelines without integrity verification.",
                impact="HIGH",
                prevalence="Uncommon",
                detectability="Average",
                technical_impact="HIGH",
                business_impact="HIGH",
                prevention_strategies=[
                    "Use digital signatures to verify software integrity",
                    "Ensure repositories and CI/CD pipelines have proper access controls",
                    "Use integrity verification for critical data",
                    "Implement software supply chain security",
                    "Review code and configuration changes"
                ],
                testing_methods=[
                    "Software integrity verification",
                    "Supply chain security assessment",
                    "CI/CD pipeline security review",
                    "Digital signature verification",
                    "Code signing validation"
                ],
                example_scenarios=[
                    "Unsigned or unverified software updates",
                    "Insecure CI/CD pipelines",
                    "Auto-update without integrity verification",
                    "Malicious plugins or libraries"
                ],
                mapped_cwes=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830"]
            ),
            "A09_2021": OWASPCategory(
                category_id="A09_2021",
                name="Security Logging and Monitoring Failures",
                description="This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time.",
                impact="LOW",
                prevalence="Widespread",
                detectability="Difficult",
                technical_impact="LOW",
                business_impact="HIGH",
                prevention_strategies=[
                    "Ensure all login and access control failures are logged",
                    "Ensure logs are generated in a format consumable by log management systems",
                    "Ensure log data is encoded correctly to prevent log injection",
                    "Establish effective monitoring and alerting",
                    "Establish incident response and recovery plans"
                ],
                testing_methods=[
                    "Log analysis",
                    "Monitoring system verification",
                    "Incident response testing",
                    "SIEM effectiveness testing",
                    "Alert mechanism verification"
                ],
                example_scenarios=[
                    "Auditable events not logged",
                    "Warnings and errors generate inadequate log messages",
                    "Logs only stored locally",
                    "No alerting process"
                ],
                mapped_cwes=["CWE-117", "CWE-223", "CWE-532", "CWE-778"]
            ),
            "A10_2021": OWASPCategory(
                category_id="A10_2021",
                name="Server-Side Request Forgery (SSRF)",
                description="SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
                impact="MEDIUM",
                prevalence="Uncommon",
                detectability="Average",
                technical_impact="HIGH",
                business_impact="MEDIUM",
                prevention_strategies=[
                    "Sanitize and validate all client-supplied input data",
                    "Enforce the URL schema, port, and destination with positive allow list",
                    "Do not send raw responses to clients",
                    "Disable HTTP redirections",
                    "Use network segmentation to separate functionality"
                ],
                testing_methods=[
                    "Input validation testing",
                    "URL manipulation testing",
                    "Network request monitoring",
                    "Internal service enumeration",
                    "Blacklist bypass testing"
                ],
                example_scenarios=[
                    "Port scan of internal servers",
                    "Access to internal services",
                    "Reading local files",
                    "Bypass of network security controls"
                ],
                mapped_cwes=["CWE-918"]
            )
        }

    def _initialize_cwe_database(self) -> Dict[str, CWEEntry]:
        """Initialize comprehensive CWE database"""
        return {
            # Access Control (A01)
            "CWE-22": CWEEntry(
                cwe_id="CWE-22",
                name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                description="The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
                weakness_type="Base",
                likelihood="High",
                impact="High",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Input Validation", "Path Canonicalization", "Sandboxing"],
                example_languages=["Java", "C", "C++", "Python", "PHP", "JavaScript"],
                related_attack_patterns=["CAPEC-126", "CAPEC-64"]
            ),
            "CWE-78": CWEEntry(
                cwe_id="CWE-78",
                name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                description="The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                weakness_type="Base",
                likelihood="High",
                impact="High",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Input Validation", "Parameterized Commands", "Escaping"],
                example_languages=["C", "C++", "Java", "Python", "PHP", "Perl", "Ruby"],
                related_attack_patterns=["CAPEC-88", "CAPEC-43"]
            ),
            "CWE-79": CWEEntry(
                cwe_id="CWE-79",
                name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                weakness_type="Base",
                likelihood="High",
                impact="Medium",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Output Encoding", "Input Validation", "Content Security Policy"],
                example_languages=["JavaScript", "HTML", "PHP", "ASP.NET", "Java", "Python"],
                related_attack_patterns=["CAPEC-86", "CAPEC-591", "CAPEC-85"]
            ),
            "CWE-89": CWEEntry(
                cwe_id="CWE-89",
                name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                description="The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                weakness_type="Base",
                likelihood="High",
                impact="High",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Parameterized Queries", "Input Validation", "Stored Procedures"],
                example_languages=["SQL", "Java", "C#", "PHP", "Python", "Ruby"],
                related_attack_patterns=["CAPEC-66", "CAPEC-7", "CAPEC-108"]
            ),
            "CWE-94": CWEEntry(
                cwe_id="CWE-94",
                name="Improper Control of Generation of Code ('Code Injection')",
                description="The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
                weakness_type="Base",
                likelihood="Medium",
                impact="High",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Input Validation", "Sandboxing", "Code Generation Restrictions"],
                example_languages=["PHP", "Python", "JavaScript", "Ruby", "Perl"],
                related_attack_patterns=["CAPEC-35", "CAPEC-242"]
            ),
            # Cryptographic Failures (A02)
            "CWE-327": CWEEntry(
                cwe_id="CWE-327",
                name="Use of a Broken or Risky Cryptographic Algorithm",
                description="The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
                weakness_type="Base",
                likelihood="Medium",
                impact="High",
                detection_methods=["Automated Static Analysis", "Manual Code Review", "Configuration Review"],
                prevention_methods=["Use Strong Cryptography", "Regular Algorithm Updates", "Cryptographic Standards"],
                example_languages=["Java", "C#", "C++", "Python", "JavaScript", "Go"],
                related_attack_patterns=["CAPEC-97", "CAPEC-463"]
            ),
            "CWE-328": CWEEntry(
                cwe_id="CWE-328",
                name="Reversible One-Way Hash",
                description="The product uses a hashing algorithm that produces a hash value that can be used to determine the original input, or to find an input that can produce the same hash, more efficiently than brute force techniques.",
                weakness_type="Base",
                likelihood="Medium",
                impact="Medium",
                detection_methods=["Automated Static Analysis", "Manual Code Review"],
                prevention_methods=["Use Cryptographic Hash Functions", "Salt Usage", "Key Stretching"],
                example_languages=["Java", "C#", "Python", "PHP", "JavaScript"],
                related_attack_patterns=["CAPEC-461", "CAPEC-97"]
            ),
            # Authentication Failures (A07)
            "CWE-287": CWEEntry(
                cwe_id="CWE-287",
                name="Improper Authentication",
                description="When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
                weakness_type="Class",
                likelihood="High",
                impact="High",
                detection_methods=["Manual Testing", "Automated Testing", "Code Review"],
                prevention_methods=["Multi-Factor Authentication", "Strong Authentication", "Session Management"],
                example_languages=["All Languages"],
                related_attack_patterns=["CAPEC-115", "CAPEC-560", "CAPEC-16"]
            ),
            "CWE-798": CWEEntry(
                cwe_id="CWE-798",
                name="Use of Hard-coded Credentials",
                description="The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
                weakness_type="Base",
                likelihood="Medium",
                impact="High",
                detection_methods=["Automated Static Analysis", "Manual Code Review"],
                prevention_methods=["External Configuration", "Credential Management", "Environment Variables"],
                example_languages=["All Languages"],
                related_attack_patterns=["CAPEC-70", "CAPEC-164"]
            ),
            # Software and Data Integrity Failures (A08)
            "CWE-502": CWEEntry(
                cwe_id="CWE-502",
                name="Deserialization of Untrusted Data",
                description="The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                weakness_type="Base",
                likelihood="Medium",
                impact="High",
                detection_methods=["Automated Static Analysis", "Dynamic Testing", "Manual Code Review"],
                prevention_methods=["Input Validation", "Safe Deserialization", "Type Checking"],
                example_languages=["Java", "Python", "C#", "PHP", "Ruby"],
                related_attack_patterns=["CAPEC-586", "CAPEC-218"]
            ),
            # SSRF (A10)
            "CWE-918": CWEEntry(
                cwe_id="CWE-918",
                name="Server-Side Request Forgery (SSRF)",
                description="The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
                weakness_type="Base",
                likelihood="Medium",
                impact="High",
                detection_methods=["Dynamic Testing", "Manual Testing", "Code Review"],
                prevention_methods=["URL Validation", "Whitelist Destinations", "Network Segmentation"],
                example_languages=["All Web Languages"],
                related_attack_patterns=["CAPEC-664", "CAPEC-141"]
            )
        }

    def _initialize_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize vulnerability detection patterns"""
        return {
            # SQL Injection patterns
            "sql_injection": {
                "cwe_id": "CWE-89",
                "owasp_category": "A03_2021",
                "patterns": [
                    r"SELECT.*FROM.*WHERE.*=.*\+",
                    r"query.*=.*\+.*user",
                    r"WHERE.*=.*\$",
                    r"execute\(.*\+.*\)",
                    r"cursor\.execute\(.*%.*\)",
                    r"db\.raw\(.*\+.*\)"
                ],
                "severity": SeverityLevel.HIGH,
                "remediation": "Use parameterized queries or prepared statements"
            },
            # XSS patterns
            "xss": {
                "cwe_id": "CWE-79",
                "owasp_category": "A03_2021",
                "patterns": [
                    r"innerHTML.*=.*user",
                    r"document\.write\(.*user",
                    r"html\(.*user",
                    r"eval\(.*user",
                    r"<script.*>.*</script>"
                ],
                "severity": SeverityLevel.MEDIUM,
                "remediation": "Use output encoding and Content Security Policy"
            },
            # Command injection patterns
            "command_injection": {
                "cwe_id": "CWE-78",
                "owasp_category": "A03_2021",
                "patterns": [
                    r"system\(.*user",
                    r"exec\(.*user",
                    r"shell_exec\(.*user",
                    r"subprocess\.call\(.*shell=True",
                    r"os\.system\(.*\+",
                    r"Runtime\.getRuntime\(\)\.exec\("
                ],
                "severity": SeverityLevel.CRITICAL,
                "remediation": "Use parameterized commands and input validation"
            },
            # Path traversal patterns
            "path_traversal": {
                "cwe_id": "CWE-22",
                "owasp_category": "A01_2021",
                "patterns": [
                    r"\.\./",
                    r"\.\.\\\\",
                    r"file.*=.*\$",
                    r"include\(.*\$",
                    r"require\(.*\$",
                    r"open\(.*user"
                ],
                "severity": SeverityLevel.HIGH,
                "remediation": "Use path canonicalization and input validation"
            },
            # Hardcoded credentials patterns
            "hardcoded_credentials": {
                "cwe_id": "CWE-798",
                "owasp_category": "A07_2021",
                "patterns": [
                    r"password\s*=\s*['\"][\w]{4,}['\"]",
                    r"api_key\s*=\s*['\"][\w]{10,}['\"]",
                    r"secret\s*=\s*['\"][\w]{8,}['\"]",
                    r"private_key\s*=\s*['\"]",
                    r"access_token\s*=\s*['\"]"
                ],
                "severity": SeverityLevel.HIGH,
                "remediation": "Use environment variables or secure credential storage"
            },
            # Weak cryptography patterns
            "weak_crypto": {
                "cwe_id": "CWE-327",
                "owasp_category": "A02_2021",
                "patterns": [
                    r"MD5\(",
                    r"SHA1\(",
                    r"hashlib\.md5\(",
                    r"hashlib\.sha1\(",
                    r"DES\(",
                    r"RC4\("
                ],
                "severity": SeverityLevel.MEDIUM,
                "remediation": "Use strong cryptographic algorithms (SHA-256, AES)"
            },
            # Insecure deserialization patterns
            "insecure_deserialization": {
                "cwe_id": "CWE-502",
                "owasp_category": "A08_2021",
                "patterns": [
                    r"pickle\.loads\(",
                    r"yaml\.load\(",
                    r"unserialize\(",
                    r"ObjectInputStream\.readObject\(",
                    r"JSON\.parse\(.*user"
                ],
                "severity": SeverityLevel.CRITICAL,
                "remediation": "Use safe deserialization methods and input validation"
            },
            # SSRF patterns
            "ssrf": {
                "cwe_id": "CWE-918",
                "owasp_category": "A10_2021",
                "patterns": [
                    r"requests\.get\(.*user",
                    r"urllib\.request\.urlopen\(.*user",
                    r"fetch\(.*user",
                    r"curl\(.*user",
                    r"HttpClient.*\.get\(.*user"
                ],
                "severity": SeverityLevel.MEDIUM,
                "remediation": "Validate URLs and use whitelist of allowed destinations"
            }
        }

    def map_vulnerability(self, vulnerability_type: str, code_snippet: str, confidence: float) -> VulnerabilityMapping:
        """Map a vulnerability to OWASP and CWE classifications"""

        pattern_info = self.vulnerability_patterns.get(vulnerability_type, {})
        cwe_id = pattern_info.get("cwe_id", "CWE-Unknown")
        owasp_category = pattern_info.get("owasp_category", "Unknown")
        severity = pattern_info.get("severity", SeverityLevel.MEDIUM)

        # Calculate CVSS score based on severity and confidence
        cvss_score = self._calculate_cvss_score(severity, confidence)

        # Determine business risk
        business_risk = self._determine_business_risk(severity, owasp_category)

        # Get compliance frameworks
        compliance_frameworks = self._get_compliance_frameworks(owasp_category, cwe_id)

        return VulnerabilityMapping(
            vulnerability_id=f"VULN-{cwe_id}-{int(confidence*100)}",
            title=f"{vulnerability_type.replace('_', ' ').title()} Vulnerability",
            description=self._get_vulnerability_description(vulnerability_type, cwe_id),
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            cvss_score=cvss_score,
            remediation_effort=self._estimate_remediation_effort(severity),
            business_risk=business_risk,
            compliance_frameworks=compliance_frameworks
        )

    def _calculate_cvss_score(self, severity: SeverityLevel, confidence: float) -> float:
        """Calculate CVSS score based on severity and confidence"""
        base_scores = {
            SeverityLevel.CRITICAL: 9.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0
        }

        base_score = base_scores.get(severity, 5.0)
        # Adjust score based on confidence
        adjusted_score = base_score * confidence
        return round(adjusted_score, 1)

    def _determine_business_risk(self, severity: SeverityLevel, owasp_category: str) -> str:
        """Determine business risk level"""
        high_business_impact_categories = ["A01_2021", "A02_2021", "A03_2021", "A07_2021", "A08_2021"]

        if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            if owasp_category in high_business_impact_categories:
                return "Critical"
            else:
                return "High"
        elif severity == SeverityLevel.MEDIUM:
            return "Medium"
        else:
            return "Low"

    def _get_compliance_frameworks(self, owasp_category: str, cwe_id: str) -> List[str]:
        """Get applicable compliance frameworks"""
        frameworks = ["OWASP Top 10 2021"]

        # Add specific frameworks based on vulnerability type
        if owasp_category in ["A02_2021", "A07_2021"]:
            frameworks.extend(["PCI DSS", "SOX", "GDPR"])

        if owasp_category in ["A01_2021", "A05_2021"]:
            frameworks.extend(["ISO 27001", "NIST Cybersecurity Framework"])

        if cwe_id in ["CWE-89", "CWE-79", "CWE-78"]:
            frameworks.append("SANS Top 25")

        return frameworks

    def _estimate_remediation_effort(self, severity: SeverityLevel) -> str:
        """Estimate remediation effort"""
        effort_mapping = {
            SeverityLevel.CRITICAL: "High (1-2 weeks)",
            SeverityLevel.HIGH: "Medium (3-5 days)",
            SeverityLevel.MEDIUM: "Low (1-2 days)",
            SeverityLevel.LOW: "Very Low (< 1 day)",
            SeverityLevel.INFO: "Minimal (< 4 hours)"
        }
        return effort_mapping.get(severity, "Medium")

    def _get_vulnerability_description(self, vulnerability_type: str, cwe_id: str) -> str:
        """Get detailed vulnerability description"""
        cwe_entry = self.cwe_database.get(cwe_id)
        if cwe_entry:
            return cwe_entry.description

        # Fallback descriptions
        descriptions = {
            "sql_injection": "SQL injection vulnerabilities allow attackers to interfere with database queries by injecting malicious SQL code.",
            "xss": "Cross-site scripting vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.",
            "command_injection": "Command injection vulnerabilities allow attackers to execute arbitrary commands on the host operating system.",
            "path_traversal": "Path traversal vulnerabilities allow attackers to access files and directories outside the intended directory.",
            "hardcoded_credentials": "Hard-coded credentials in source code can be discovered by attackers and used for unauthorized access.",
            "weak_crypto": "Use of weak cryptographic algorithms can allow attackers to break encryption and access sensitive data.",
            "insecure_deserialization": "Insecure deserialization can lead to remote code execution and other attacks.",
            "ssrf": "Server-side request forgery allows attackers to make requests from the server to internal or external systems."
        }

        return descriptions.get(vulnerability_type, "Unknown vulnerability type")

    def get_owasp_category_details(self, category_id: str) -> Optional[OWASPCategory]:
        """Get detailed information about an OWASP category"""
        return self.owasp_categories.get(category_id)

    def get_cwe_details(self, cwe_id: str) -> Optional[CWEEntry]:
        """Get detailed information about a CWE"""
        return self.cwe_database.get(cwe_id)

    def generate_compliance_report(self, vulnerabilities: List[VulnerabilityMapping]) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""

        # Count vulnerabilities by OWASP category
        owasp_counts = {}
        for vuln in vulnerabilities:
            category = vuln.owasp_category
            if category not in owasp_counts:
                owasp_counts[category] = 0
            owasp_counts[category] += 1

        # Count vulnerabilities by CWE
        cwe_counts = {}
        for vuln in vulnerabilities:
            cwe = vuln.cwe_id
            if cwe not in cwe_counts:
                cwe_counts[cwe] = 0
            cwe_counts[cwe] += 1

        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1

        # Risk assessment
        total_critical = severity_counts.get("CRITICAL", 0)
        total_high = severity_counts.get("HIGH", 0)
        total_vulnerabilities = len(vulnerabilities)

        if total_critical > 0:
            overall_risk = "Critical"
        elif total_high > 5:
            overall_risk = "High"
        elif total_high > 0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"

        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_vulnerabilities": total_vulnerabilities,
                "overall_risk_level": overall_risk,
                "frameworks_assessed": ["OWASP Top 10 2021", "CWE Database"]
            },
            "owasp_top10_breakdown": owasp_counts,
            "cwe_breakdown": cwe_counts,
            "severity_breakdown": severity_counts,
            "compliance_summary": {
                "owasp_categories_affected": len(owasp_counts),
                "total_owasp_categories": len(self.owasp_categories),
                "coverage_percentage": round((len(owasp_counts) / len(self.owasp_categories)) * 100, 2)
            },
            "risk_metrics": {
                "critical_vulnerabilities": total_critical,
                "high_vulnerabilities": total_high,
                "medium_vulnerabilities": severity_counts.get("MEDIUM", 0),
                "low_vulnerabilities": severity_counts.get("LOW", 0),
                "info_vulnerabilities": severity_counts.get("INFO", 0)
            },
            "recommendations": self._generate_recommendations(vulnerabilities, owasp_counts, severity_counts)
        }

    def _generate_recommendations(self, vulnerabilities: List[VulnerabilityMapping],
                                 owasp_counts: Dict[str, int],
                                 severity_counts: Dict[str, int]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Critical findings
        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Address all critical vulnerabilities within 24-48 hours")

        # High findings
        if severity_counts.get("HIGH", 0) > 5:
            recommendations.append("⚠️ HIGH PRIORITY: Multiple high-severity vulnerabilities require immediate attention")

        # OWASP specific recommendations
        if "A03_2021" in owasp_counts:  # Injection
            recommendations.append("🔍 Implement input validation and parameterized queries to prevent injection attacks")

        if "A01_2021" in owasp_counts:  # Broken Access Control
            recommendations.append("🔒 Review and strengthen access control mechanisms")

        if "A02_2021" in owasp_counts:  # Cryptographic Failures
            recommendations.append("🔐 Upgrade cryptographic implementations and protect sensitive data")

        if "A07_2021" in owasp_counts:  # Authentication Failures
            recommendations.append("👤 Implement multi-factor authentication and strengthen authentication mechanisms")

        # General recommendations
        recommendations.extend([
            "📊 Implement security testing in CI/CD pipeline",
            "📖 Provide security training for development team",
            "🔄 Establish regular security assessments",
            "📋 Create incident response procedures"
        ])

        return recommendations

# Usage example and testing
if __name__ == "__main__":
    # Initialize the mapper
    mapper = OWASPCWEMapper()

    # Example vulnerability mapping
    sql_injection_mapping = mapper.map_vulnerability(
        vulnerability_type="sql_injection",
        code_snippet="SELECT * FROM users WHERE id = '" + user_id + "'",
        confidence=0.95
    )

    print("SQL Injection Mapping:")
    print(json.dumps(asdict(sql_injection_mapping), indent=2))

    # Example compliance report
    sample_vulnerabilities = [
        mapper.map_vulnerability("sql_injection", "query", 0.9),
        mapper.map_vulnerability("xss", "innerHTML", 0.8),
        mapper.map_vulnerability("command_injection", "system()", 0.95),
        mapper.map_vulnerability("hardcoded_credentials", "password='123'", 0.7)
    ]

    compliance_report = mapper.generate_compliance_report(sample_vulnerabilities)
    print("\nCompliance Report:")
    print(json.dumps(compliance_report, indent=2))