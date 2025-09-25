"""
Bugcrowd Vulnerability Rating Taxonomy Integration
Advanced vulnerability classification and scoring system
"""
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import requests
import asyncio

@dataclass
class BugcrowdVulnerability:
    """Bugcrowd vulnerability classification structure"""
    category: str
    subcategory: str
    severity: str
    impact: str
    likelihood: str
    cvss_score: float
    bugcrowd_priority: str
    description: str
    exploitation_requirements: List[str]
    remediation_guidance: List[str]
    references: List[str]
    examples: List[str]

class BugcrowdTaxonomy:
    """
    Comprehensive Bugcrowd Vulnerability Rating Taxonomy Integration

    Provides professional vulnerability classification, scoring, and reporting
    based on Bugcrowd's industry-standard taxonomy.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.taxonomy_data = {}
        self.vulnerability_categories = {}
        self.severity_matrix = {}
        self._initialize_taxonomy()

    def _initialize_taxonomy(self):
        """Initialize Bugcrowd taxonomy data"""
        try:
            self.taxonomy_data = {
                # Web Application Vulnerabilities
                "web_application": {
                    "cross_site_scripting": {
                        "reflected": {
                            "severity_range": "Low-High",
                            "typical_cvss": "6.1-8.8",
                            "bugcrowd_priority": "P3-P1",
                            "description": "User input reflected in response without proper sanitization",
                            "exploitation": ["User interaction required", "Malicious link/form"],
                            "remediation": ["Input validation", "Output encoding", "CSP headers"],
                            "examples": ["Search parameter reflection", "Error message XSS"]
                        },
                        "stored": {
                            "severity_range": "Medium-Critical",
                            "typical_cvss": "5.4-9.6",
                            "bugcrowd_priority": "P2-P1",
                            "description": "Malicious script stored and executed for other users",
                            "exploitation": ["Persistent payload", "Affects multiple users"],
                            "remediation": ["Input sanitization", "Output encoding", "Content filtering"],
                            "examples": ["Comment section XSS", "Profile field XSS"]
                        },
                        "dom_based": {
                            "severity_range": "Low-High",
                            "typical_cvss": "6.1-8.8",
                            "bugcrowd_priority": "P3-P1",
                            "description": "Client-side script manipulation of DOM",
                            "exploitation": ["Browser-based", "URL fragment manipulation"],
                            "remediation": ["Safe DOM manipulation", "Input validation"],
                            "examples": ["JavaScript URL parsing", "Hash-based XSS"]
                        }
                    },
                    "sql_injection": {
                        "classic": {
                            "severity_range": "High-Critical",
                            "typical_cvss": "7.5-9.8",
                            "bugcrowd_priority": "P2-P1",
                            "description": "Direct SQL query manipulation",
                            "exploitation": ["Database access", "Data extraction"],
                            "remediation": ["Parameterized queries", "Input validation", "Least privilege"],
                            "examples": ["Login bypass", "Union-based extraction"]
                        },
                        "blind": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "6.5-8.5",
                            "bugcrowd_priority": "P2-P1",
                            "description": "SQL injection without direct output",
                            "exploitation": ["Boolean-based", "Time-based"],
                            "remediation": ["Parameterized queries", "Error handling"],
                            "examples": ["Time-based enumeration", "Boolean conditions"]
                        },
                        "second_order": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "6.0-8.0",
                            "bugcrowd_priority": "P2-P1",
                            "description": "SQL injection via stored data",
                            "exploitation": ["Two-step process", "Stored payload execution"],
                            "remediation": ["Input validation", "Output sanitization"],
                            "examples": ["Registration->Login SQLi", "Profile update injection"]
                        }
                    },
                    "authentication": {
                        "broken_authentication": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "6.5-8.1",
                            "bugcrowd_priority": "P2-P1",
                            "description": "Authentication mechanism flaws",
                            "exploitation": ["Session hijacking", "Credential bypass"],
                            "remediation": ["Strong session management", "Multi-factor authentication"],
                            "examples": ["Session fixation", "Weak password reset"]
                        },
                        "session_management": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "5.9-7.5",
                            "bugcrowd_priority": "P3-P1",
                            "description": "Session handling vulnerabilities",
                            "exploitation": ["Session hijacking", "Privilege escalation"],
                            "remediation": ["Secure session handling", "Session timeout"],
                            "examples": ["Predictable session IDs", "Session not invalidated"]
                        }
                    }
                },

                # Mobile Application Vulnerabilities
                "mobile_application": {
                    "insecure_data_storage": {
                        "local_storage": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "5.5-7.1",
                            "bugcrowd_priority": "P3-P2",
                            "description": "Sensitive data stored insecurely on device",
                            "exploitation": ["Device access", "Data extraction"],
                            "remediation": ["Data encryption", "Secure storage APIs"],
                            "examples": ["Unencrypted databases", "Plain text credentials"]
                        }
                    },
                    "insecure_communication": {
                        "network_traffic": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "6.1-8.1",
                            "bugcrowd_priority": "P3-P1",
                            "description": "Unencrypted or poorly encrypted communications",
                            "exploitation": ["Man-in-the-middle", "Traffic interception"],
                            "remediation": ["TLS implementation", "Certificate pinning"],
                            "examples": ["HTTP usage", "Weak TLS configuration"]
                        }
                    }
                },

                # API Security
                "api_security": {
                    "broken_object_level_authorization": {
                        "idor": {
                            "severity_range": "Medium-High",
                            "typical_cvss": "6.1-8.5",
                            "bugcrowd_priority": "P3-P1",
                            "description": "Direct object reference without authorization",
                            "exploitation": ["Parameter manipulation", "Data access"],
                            "remediation": ["Authorization checks", "Indirect references"],
                            "examples": ["User ID enumeration", "Document access bypass"]
                        }
                    },
                    "broken_authentication": {
                        "api_key_exposure": {
                            "severity_range": "Medium-Critical",
                            "typical_cvss": "6.5-9.1",
                            "bugcrowd_priority": "P2-P1",
                            "description": "API keys exposed or weakly protected",
                            "exploitation": ["API abuse", "Data access"],
                            "remediation": ["Key rotation", "Secure storage", "Rate limiting"],
                            "examples": ["Hardcoded keys", "Public repository exposure"]
                        }
                    }
                },

                # Infrastructure Vulnerabilities
                "infrastructure": {
                    "server_security_misconfiguration": {
                        "default_credentials": {
                            "severity_range": "High-Critical",
                            "typical_cvss": "7.5-9.8",
                            "bugcrowd_priority": "P2-P1",
                            "description": "Default or weak administrative credentials",
                            "exploitation": ["System access", "Full compromise"],
                            "remediation": ["Strong passwords", "Default credential change"],
                            "examples": ["admin:admin", "Default database passwords"]
                        }
                    }
                }
            }

            self.severity_matrix = {
                "Critical": {"cvss_range": (9.0, 10.0), "priority": "P1", "color": "#dc3545"},
                "High": {"cvss_range": (7.0, 8.9), "priority": "P1-P2", "color": "#fd7e14"},
                "Medium": {"cvss_range": (4.0, 6.9), "priority": "P2-P3", "color": "#ffc107"},
                "Low": {"cvss_range": (0.1, 3.9), "priority": "P3-P4", "color": "#28a745"},
                "Informational": {"cvss_range": (0.0, 0.0), "priority": "P4", "color": "#6c757d"}
            }

            self.logger.info("🏆 Bugcrowd Taxonomy initialized with comprehensive vulnerability classifications")

        except Exception as e:
            self.logger.error(f"Failed to initialize Bugcrowd taxonomy: {e}")
            self.taxonomy_data = {}

    async def classify_vulnerability(self, vulnerability_data: Dict[str, Any]) -> BugcrowdVulnerability:
        """Classify vulnerability using Bugcrowd taxonomy"""
        try:
            # Extract key information
            vuln_type = vulnerability_data.get('type', '').lower()
            description = vulnerability_data.get('description', '')
            impact = vulnerability_data.get('impact', 'medium')

            # Classify based on type and characteristics
            classification = await self._match_vulnerability_pattern(vuln_type, description)

            # Calculate CVSS score and severity
            cvss_score = await self._calculate_cvss_score(vulnerability_data, classification)
            severity = self._get_severity_from_cvss(cvss_score)

            # Get Bugcrowd priority
            bugcrowd_priority = self._get_bugcrowd_priority(severity, classification)

            # Generate comprehensive vulnerability object
            bugcrowd_vuln = BugcrowdVulnerability(
                category=classification.get('category', 'Other'),
                subcategory=classification.get('subcategory', 'Unknown'),
                severity=severity,
                impact=impact,
                likelihood=classification.get('likelihood', 'medium'),
                cvss_score=cvss_score,
                bugcrowd_priority=bugcrowd_priority,
                description=classification.get('description', description),
                exploitation_requirements=classification.get('exploitation', []),
                remediation_guidance=classification.get('remediation', []),
                references=await self._get_vulnerability_references(classification),
                examples=classification.get('examples', [])
            )

            self.logger.info(f"🏆 Classified vulnerability: {bugcrowd_vuln.category}/{bugcrowd_vuln.subcategory} - {severity}")
            return bugcrowd_vuln

        except Exception as e:
            self.logger.error(f"Failed to classify vulnerability: {e}")
            # Return default classification
            return BugcrowdVulnerability(
                category="Unknown",
                subcategory="Unknown",
                severity="Medium",
                impact=impact,
                likelihood="medium",
                cvss_score=5.0,
                bugcrowd_priority="P3",
                description=description,
                exploitation_requirements=[],
                remediation_guidance=["Review security configuration"],
                references=[],
                examples=[]
            )

    async def _match_vulnerability_pattern(self, vuln_type: str, description: str) -> Dict[str, Any]:
        """Match vulnerability to Bugcrowd taxonomy patterns"""
        try:
            # XSS Detection
            if any(keyword in vuln_type for keyword in ['xss', 'cross-site', 'script']):
                if 'stored' in description.lower():
                    return self.taxonomy_data['web_application']['cross_site_scripting']['stored']
                elif 'dom' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['cross_site_scripting']['dom_based'],
                        'web_application', 'cross_site_scripting'
                    )
                else:
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['cross_site_scripting']['reflected'],
                        'web_application', 'cross_site_scripting'
                    )

            # SQL Injection Detection
            elif any(keyword in vuln_type for keyword in ['sql', 'injection', 'sqli']):
                if 'blind' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['sql_injection']['blind'],
                        'web_application', 'sql_injection'
                    )
                elif 'second' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['sql_injection']['second_order'],
                        'web_application', 'sql_injection'
                    )
                else:
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['sql_injection']['classic'],
                        'web_application', 'sql_injection'
                    )

            # Authentication Issues
            elif any(keyword in vuln_type for keyword in ['auth', 'session', 'login']):
                if 'session' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['authentication']['session_management'],
                        'web_application', 'authentication'
                    )
                else:
                    return self._enhance_classification(
                        self.taxonomy_data['web_application']['authentication']['broken_authentication'],
                        'web_application', 'authentication'
                    )

            # API Security Issues
            elif any(keyword in vuln_type for keyword in ['api', 'idor', 'bola']):
                if 'key' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['api_security']['broken_authentication']['api_key_exposure'],
                        'api_security', 'broken_authentication'
                    )
                else:
                    return self._enhance_classification(
                        self.taxonomy_data['api_security']['broken_object_level_authorization']['idor'],
                        'api_security', 'broken_object_level_authorization'
                    )

            # Infrastructure Issues
            elif any(keyword in vuln_type for keyword in ['config', 'default', 'server']):
                return self._enhance_classification(
                    self.taxonomy_data['infrastructure']['server_security_misconfiguration']['default_credentials'],
                    'infrastructure', 'server_security_misconfiguration'
                )

            # Mobile Issues
            elif any(keyword in vuln_type for keyword in ['mobile', 'app', 'android', 'ios']):
                if 'storage' in description.lower():
                    return self._enhance_classification(
                        self.taxonomy_data['mobile_application']['insecure_data_storage']['local_storage'],
                        'mobile_application', 'insecure_data_storage'
                    )
                else:
                    return self._enhance_classification(
                        self.taxonomy_data['mobile_application']['insecure_communication']['network_traffic'],
                        'mobile_application', 'insecure_communication'
                    )

            # Default classification
            else:
                return {
                    'category': 'Other',
                    'subcategory': 'Unknown',
                    'severity_range': 'Low-Medium',
                    'typical_cvss': '3.0-6.0',
                    'bugcrowd_priority': 'P3-P4',
                    'description': 'Unclassified security issue',
                    'exploitation': ['Varies'],
                    'remediation': ['Review security configuration'],
                    'examples': []
                }

        except Exception as e:
            self.logger.error(f"Failed to match vulnerability pattern: {e}")
            return {}

    def _enhance_classification(self, base_classification: Dict[str, Any],
                              category: str, subcategory: str) -> Dict[str, Any]:
        """Enhance classification with category information"""
        enhanced = base_classification.copy()
        enhanced['category'] = category
        enhanced['subcategory'] = subcategory
        return enhanced

    async def _calculate_cvss_score(self, vulnerability_data: Dict[str, Any],
                                  classification: Dict[str, Any]) -> float:
        """Calculate CVSS score based on vulnerability characteristics"""
        try:
            # Base CVSS calculation factors
            base_score = 5.0  # Default medium score

            # Adjust based on classification
            severity_range = classification.get('typical_cvss', '5.0-6.0')
            if '-' in severity_range:
                min_score, max_score = map(float, severity_range.split('-'))
                base_score = (min_score + max_score) / 2
            else:
                base_score = float(severity_range)

            # Adjust based on additional factors
            impact_factor = {
                'low': 0.8,
                'medium': 1.0,
                'high': 1.3,
                'critical': 1.5
            }.get(vulnerability_data.get('impact', 'medium').lower(), 1.0)

            # Adjust based on exploitability
            exploit_requirements = classification.get('exploitation', [])
            exploitability_factor = 1.0

            if any('user interaction' in req.lower() for req in exploit_requirements):
                exploitability_factor *= 0.9
            if any('authenticated' in req.lower() for req in exploit_requirements):
                exploitability_factor *= 0.85
            if any('network access' in req.lower() for req in exploit_requirements):
                exploitability_factor *= 1.1

            # Calculate final score
            final_score = min(10.0, base_score * impact_factor * exploitability_factor)
            return round(final_score, 1)

        except Exception as e:
            self.logger.error(f"Failed to calculate CVSS score: {e}")
            return 5.0

    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Get severity level from CVSS score"""
        for severity, details in self.severity_matrix.items():
            min_score, max_score = details['cvss_range']
            if min_score <= cvss_score <= max_score:
                return severity
        return "Medium"

    def _get_bugcrowd_priority(self, severity: str, classification: Dict[str, Any]) -> str:
        """Get Bugcrowd priority based on severity and classification"""
        try:
            # Get priority from classification
            classification_priority = classification.get('bugcrowd_priority', 'P3')

            # Adjust based on severity
            severity_priority = self.severity_matrix.get(severity, {}).get('priority', 'P3')

            # Return the higher priority (lower P number)
            priorities = [classification_priority, severity_priority]
            priority_values = []

            for priority in priorities:
                if '-' in priority:
                    # Handle range like "P1-P2"
                    priority_values.append(int(priority.split('-')[0][1:]))
                else:
                    priority_values.append(int(priority[1:]))

            return f"P{min(priority_values)}"

        except Exception as e:
            self.logger.error(f"Failed to determine Bugcrowd priority: {e}")
            return "P3"

    async def _get_vulnerability_references(self, classification: Dict[str, Any]) -> List[str]:
        """Get relevant references for vulnerability type"""
        references = []

        category = classification.get('category', '')
        subcategory = classification.get('subcategory', '')

        # Add general references
        references.append("https://bugcrowd.com/vulnerability-rating-taxonomy")

        # Add category-specific references
        if category == 'web_application':
            references.extend([
                "https://owasp.org/www-project-top-ten/",
                "https://owasp.org/www-project-web-security-testing-guide/"
            ])
        elif category == 'api_security':
            references.extend([
                "https://owasp.org/www-project-api-security/",
                "https://github.com/OWASP/API-Security/blob/master/2019/en/dist/owasp-api-security-top-10.pdf"
            ])
        elif category == 'mobile_application':
            references.extend([
                "https://owasp.org/www-project-mobile-top-10/",
                "https://github.com/OWASP/owasp-mstg"
            ])

        return references

    async def generate_bugcrowd_report(self, vulnerabilities: List[BugcrowdVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive Bugcrowd-style vulnerability report"""
        try:
            # Sort vulnerabilities by priority
            sorted_vulns = sorted(vulnerabilities, key=lambda v: int(v.bugcrowd_priority[1:]))

            # Calculate statistics
            severity_counts = {}
            priority_counts = {}
            category_counts = {}

            for vuln in vulnerabilities:
                # Count by severity
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

                # Count by priority
                priority_counts[vuln.bugcrowd_priority] = priority_counts.get(vuln.bugcrowd_priority, 0) + 1

                # Count by category
                category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1

            # Calculate risk score
            risk_score = await self._calculate_overall_risk_score(vulnerabilities)

            # Generate executive summary
            executive_summary = await self._generate_executive_summary(
                vulnerabilities, risk_score, severity_counts
            )

            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "Bugcrowd Professional Assessment",
                    "taxonomy_version": "2024.1",
                    "total_vulnerabilities": len(vulnerabilities),
                    "overall_risk_score": risk_score
                },
                "executive_summary": executive_summary,
                "statistics": {
                    "severity_distribution": severity_counts,
                    "priority_distribution": priority_counts,
                    "category_distribution": category_counts,
                    "average_cvss_score": round(sum(v.cvss_score for v in vulnerabilities) / len(vulnerabilities), 1) if vulnerabilities else 0
                },
                "vulnerabilities": [asdict(vuln) for vuln in sorted_vulns],
                "remediation_roadmap": await self._generate_remediation_roadmap(sorted_vulns),
                "compliance_mapping": await self._generate_compliance_mapping(vulnerabilities)
            }

            self.logger.info(f"🏆 Generated Bugcrowd report with {len(vulnerabilities)} vulnerabilities")
            return report

        except Exception as e:
            self.logger.error(f"Failed to generate Bugcrowd report: {e}")
            return {"error": str(e)}

    async def _calculate_overall_risk_score(self, vulnerabilities: List[BugcrowdVulnerability]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0

        # Weight vulnerabilities by priority
        priority_weights = {"P1": 10, "P2": 7, "P3": 4, "P4": 1}

        total_weighted_score = 0
        total_weights = 0

        for vuln in vulnerabilities:
            weight = priority_weights.get(vuln.bugcrowd_priority, 1)
            total_weighted_score += vuln.cvss_score * weight
            total_weights += weight

        return round(total_weighted_score / total_weights, 1) if total_weights > 0 else 0.0

    async def _generate_executive_summary(self, vulnerabilities: List[BugcrowdVulnerability],
                                        risk_score: float, severity_counts: Dict[str, int]) -> Dict[str, Any]:
        """Generate executive summary for the report"""

        critical_count = severity_counts.get("Critical", 0)
        high_count = severity_counts.get("High", 0)

        risk_level = "Low"
        if risk_score >= 9.0:
            risk_level = "Critical"
        elif risk_score >= 7.0:
            risk_level = "High"
        elif risk_score >= 4.0:
            risk_level = "Medium"

        return {
            "overall_risk_level": risk_level,
            "risk_score": risk_score,
            "key_findings": {
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "immediate_action_required": critical_count + high_count > 0
            },
            "recommendations": [
                "Address all Critical and High severity vulnerabilities immediately",
                "Implement security testing in development lifecycle",
                "Establish regular security assessment schedule",
                "Consider bug bounty program for continuous testing"
            ]
        }

    async def _generate_remediation_roadmap(self, vulnerabilities: List[BugcrowdVulnerability]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation roadmap"""
        roadmap = []

        # Group by priority and create roadmap items
        priority_groups = {}
        for vuln in vulnerabilities:
            priority = vuln.bugcrowd_priority
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(vuln)

        # Generate roadmap phases
        phase_mapping = {"P1": "Immediate", "P2": "Short-term", "P3": "Medium-term", "P4": "Long-term"}

        for priority in sorted(priority_groups.keys(), key=lambda x: int(x[1:])):
            vulns = priority_groups[priority]
            roadmap.append({
                "phase": phase_mapping.get(priority, "Future"),
                "timeline": self._get_timeline_for_priority(priority),
                "vulnerability_count": len(vulns),
                "categories": list(set(v.category for v in vulns)),
                "estimated_effort": self._estimate_remediation_effort(vulns),
                "business_impact": self._assess_business_impact(vulns)
            })

        return roadmap

    def _get_timeline_for_priority(self, priority: str) -> str:
        """Get recommended timeline for priority level"""
        timelines = {
            "P1": "0-7 days",
            "P2": "1-4 weeks",
            "P3": "1-3 months",
            "P4": "3-6 months"
        }
        return timelines.get(priority, "Future consideration")

    def _estimate_remediation_effort(self, vulnerabilities: List[BugcrowdVulnerability]) -> str:
        """Estimate remediation effort for vulnerabilities"""
        if len(vulnerabilities) <= 2:
            return "Low"
        elif len(vulnerabilities) <= 5:
            return "Medium"
        else:
            return "High"

    def _assess_business_impact(self, vulnerabilities: List[BugcrowdVulnerability]) -> str:
        """Assess business impact of vulnerabilities"""
        max_cvss = max(v.cvss_score for v in vulnerabilities) if vulnerabilities else 0

        if max_cvss >= 9.0:
            return "Critical business impact - potential data breach"
        elif max_cvss >= 7.0:
            return "High business impact - significant security risk"
        elif max_cvss >= 4.0:
            return "Medium business impact - moderate security risk"
        else:
            return "Low business impact - minimal security risk"

    async def _generate_compliance_mapping(self, vulnerabilities: List[BugcrowdVulnerability]) -> Dict[str, Any]:
        """Map vulnerabilities to compliance frameworks"""

        compliance_mapping = {
            "owasp_top_10": {},
            "pci_dss": {},
            "nist_csf": {},
            "iso_27001": {}
        }

        for vuln in vulnerabilities:
            # OWASP Top 10 mapping
            if vuln.category == "web_application":
                if "cross_site_scripting" in vuln.subcategory:
                    compliance_mapping["owasp_top_10"]["A07:2021 – Identification and Authentication Failures"] = True
                elif "sql_injection" in vuln.subcategory:
                    compliance_mapping["owasp_top_10"]["A03:2021 – Injection"] = True

        return compliance_mapping

# Global Bugcrowd taxonomy instance
bugcrowd_taxonomy = BugcrowdTaxonomy()