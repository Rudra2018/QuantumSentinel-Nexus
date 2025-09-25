#!/usr/bin/env python3
"""
🧠 UNIFIED INTELLIGENCE LAYER - CROSS-MODAL CORRELATION
======================================================
Advanced intelligence layer that correlates findings from SAST, DAST,
binary analysis, and threat intelligence to understand attack paths,
vulnerability chains, and predict real-world exploit impact.
"""

import asyncio
import json
import numpy as np
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import logging
from collections import defaultdict, Counter
import hashlib
import math

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.nn import GCNConv, GATConv, TransformerConv
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    import pandas as pd
    ML_AVAILABLE = True
except ImportError as e:
    logging.warning(f"ML libraries not available: {e}")
    ML_AVAILABLE = False

class FindingSource(Enum):
    SAST = "sast"
    DAST = "dast"
    BINARY_ANALYSIS = "binary_analysis"
    MOBILE_SECURITY = "mobile_security"
    OSINT = "osint"
    THREAT_INTELLIGENCE = "threat_intelligence"
    HUMAN_ANALYST = "human_analyst"

class CorrelationType(Enum):
    DIRECT_CHAIN = "direct_chain"          # A→B direct vulnerability chain
    AMPLIFICATION = "amplification"        # A + B = worse impact
    CONFIRMATION = "confirmation"          # Multiple sources confirm same vuln
    CONTEXT_ENHANCEMENT = "context"        # One finding provides context for another
    ATTACK_PATH = "attack_path"           # Multiple findings form attack path
    FALSE_POSITIVE_REDUCTION = "fp_reduction"  # One finding disproves another

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class UnifiedFinding:
    """Unified representation of security findings from any source"""
    finding_id: str
    source: FindingSource
    finding_type: str
    title: str
    description: str
    severity: str
    confidence: float
    asset: str
    location: Dict[str, Any]  # File, line, function, endpoint, etc.
    evidence: Dict[str, Any]
    technical_details: Dict[str, Any]
    business_impact: str
    remediation: List[str]
    timestamps: Dict[str, datetime]
    metadata: Dict[str, Any]

@dataclass
class VulnerabilityChain:
    """Represents a chain of vulnerabilities that can be exploited together"""
    chain_id: str
    findings: List[UnifiedFinding]
    attack_path: List[str]
    combined_severity: str
    exploit_complexity: str
    chaining_confidence: float
    business_impact_amplification: float
    proof_of_concept: Optional[str]
    mitigation_strategy: List[str]

@dataclass
class AttackScenario:
    """Complete attack scenario derived from correlated findings"""
    scenario_id: str
    name: str
    description: str
    attack_chains: List[VulnerabilityChain]
    required_conditions: List[str]
    success_probability: float
    potential_impact: Dict[str, Any]
    timeline_estimate: str
    detection_difficulty: str
    mitigation_cost: str

@dataclass
class IntelligenceInsight:
    """High-level intelligence insight derived from correlation analysis"""
    insight_id: str
    insight_type: str
    confidence: float
    description: str
    supporting_evidence: List[str]
    actionable_recommendations: List[str]
    business_priority: str
    technical_complexity: str

class CrossModalCorrelationEngine:
    """
    Advanced correlation engine that identifies relationships between
    findings from different security testing modalities
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session_id = f"CORR-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Core correlation components
        self.similarity_engine = FindingSimilarityEngine()
        self.graph_analyzer = VulnerabilityGraphAnalyzer()
        self.attack_path_finder = AttackPathFinder()
        self.risk_calculator = RiskCalculator()

        # Machine learning models
        if ML_AVAILABLE:
            self.correlation_model = CorrelationNeuralNetwork()
            self.anomaly_detector = AnomalyDetector()
            self.impact_predictor = ImpactPredictor()

        # Knowledge bases
        self.vulnerability_taxonomy = VulnerabilityTaxonomy()
        self.attack_pattern_db = AttackPatternDatabase()
        self.correlation_rules = CorrelationRuleEngine()

        # Results storage
        self.unified_findings = []
        self.vulnerability_chains = []
        self.attack_scenarios = []
        self.intelligence_insights = []

    async def correlate_findings(self, findings_by_source: Dict[FindingSource, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Main correlation function that processes findings from all sources
        """
        logging.info("Starting cross-modal finding correlation")

        correlation_results = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "sources_analyzed": list(findings_by_source.keys()),
            "total_findings": sum(len(findings) for findings in findings_by_source.values()),
            "unified_findings": [],
            "vulnerability_chains": [],
            "attack_scenarios": [],
            "intelligence_insights": [],
            "risk_assessment": {},
            "correlation_metrics": {}
        }

        try:
            # Phase 1: Normalize and unify findings from different sources
            logging.info("Phase 1: Normalizing findings")
            self.unified_findings = await self._normalize_findings(findings_by_source)

            # Phase 2: Calculate similarity and relationships
            logging.info("Phase 2: Calculating finding similarities")
            similarity_matrix = await self._calculate_similarity_matrix(self.unified_findings)

            # Phase 3: Build vulnerability correlation graph
            logging.info("Phase 3: Building vulnerability graph")
            vulnerability_graph = await self._build_vulnerability_graph(self.unified_findings, similarity_matrix)

            # Phase 4: Identify vulnerability chains and attack paths
            logging.info("Phase 4: Identifying vulnerability chains")
            self.vulnerability_chains = await self._identify_vulnerability_chains(vulnerability_graph)

            # Phase 5: Generate attack scenarios
            logging.info("Phase 5: Generating attack scenarios")
            self.attack_scenarios = await self._generate_attack_scenarios(self.vulnerability_chains)

            # Phase 6: Extract high-level intelligence insights
            logging.info("Phase 6: Extracting intelligence insights")
            self.intelligence_insights = await self._extract_intelligence_insights(
                self.unified_findings, self.vulnerability_chains, self.attack_scenarios
            )

            # Phase 7: Comprehensive risk assessment
            logging.info("Phase 7: Conducting risk assessment")
            risk_assessment = await self._conduct_risk_assessment(
                self.unified_findings, self.vulnerability_chains, self.attack_scenarios
            )

            # Phase 8: Generate correlation metrics
            correlation_metrics = await self._calculate_correlation_metrics(
                self.unified_findings, similarity_matrix, self.vulnerability_chains
            )

            # Compile results
            correlation_results.update({
                "unified_findings": [asdict(f) for f in self.unified_findings],
                "vulnerability_chains": [asdict(c) for c in self.vulnerability_chains],
                "attack_scenarios": [asdict(s) for s in self.attack_scenarios],
                "intelligence_insights": [asdict(i) for i in self.intelligence_insights],
                "risk_assessment": risk_assessment,
                "correlation_metrics": correlation_metrics,
                "end_time": datetime.now().isoformat()
            })

        except Exception as e:
            logging.error(f"Correlation analysis failed: {e}")
            correlation_results["error"] = str(e)

        return correlation_results

    async def _normalize_findings(self, findings_by_source: Dict[FindingSource, List[Dict[str, Any]]]) -> List[UnifiedFinding]:
        """Normalize findings from different sources into unified format"""
        unified_findings = []

        for source, findings in findings_by_source.items():
            for finding in findings:
                unified_finding = await self._normalize_single_finding(source, finding)
                if unified_finding:
                    unified_findings.append(unified_finding)

        logging.info(f"Normalized {len(unified_findings)} findings from {len(findings_by_source)} sources")
        return unified_findings

    async def _normalize_single_finding(self, source: FindingSource, finding: Dict[str, Any]) -> Optional[UnifiedFinding]:
        """Normalize a single finding based on its source"""
        try:
            # Extract common fields with source-specific mapping
            finding_id = f"{source.value}_{finding.get('id', hashlib.md5(str(finding).encode()).hexdigest()[:8])}"

            # Map source-specific fields to unified format
            if source == FindingSource.SAST:
                return await self._normalize_sast_finding(finding_id, finding)
            elif source == FindingSource.DAST:
                return await self._normalize_dast_finding(finding_id, finding)
            elif source == FindingSource.BINARY_ANALYSIS:
                return await self._normalize_binary_finding(finding_id, finding)
            elif source == FindingSource.MOBILE_SECURITY:
                return await self._normalize_mobile_finding(finding_id, finding)
            elif source == FindingSource.OSINT:
                return await self._normalize_osint_finding(finding_id, finding)
            elif source == FindingSource.THREAT_INTELLIGENCE:
                return await self._normalize_threat_intel_finding(finding_id, finding)
            else:
                return await self._normalize_generic_finding(finding_id, source, finding)

        except Exception as e:
            logging.error(f"Failed to normalize finding from {source.value}: {e}")
            return None

    async def _normalize_sast_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize SAST finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.SAST,
            finding_type=finding.get("type", "code_vulnerability"),
            title=finding.get("title", finding.get("type", "Unknown SAST Finding")),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.5),
            asset=finding.get("file_path", finding.get("asset", "")),
            location={
                "file": finding.get("file_path", ""),
                "line": finding.get("line_number", 0),
                "function": finding.get("function_name", ""),
                "code_snippet": finding.get("code_snippet", "")
            },
            evidence={
                "pattern_matched": finding.get("pattern", ""),
                "rule_id": finding.get("rule_id", ""),
                "source_analysis": finding.get("analysis", {})
            },
            technical_details={
                "vulnerability_class": finding.get("vuln_class", ""),
                "attack_vector": finding.get("attack_vector", ""),
                "data_flow": finding.get("data_flow", []),
                "control_flow": finding.get("control_flow", [])
            },
            business_impact=finding.get("business_impact", "medium"),
            remediation=finding.get("remediation", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_dast_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize DAST finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.DAST,
            finding_type=finding.get("vuln_type", "web_vulnerability"),
            title=finding.get("title", f"DAST: {finding.get('vuln_type', 'Unknown')}"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.5),
            asset=finding.get("endpoint", {}).get("url", ""),
            location={
                "url": finding.get("endpoint", {}).get("url", ""),
                "method": finding.get("endpoint", {}).get("method", ""),
                "parameter": finding.get("parameter", ""),
                "endpoint_details": finding.get("endpoint", {})
            },
            evidence={
                "payload": finding.get("payload", ""),
                "response": finding.get("response", {}),
                "proof_of_concept": finding.get("proof_of_concept", "")
            },
            technical_details={
                "attack_type": finding.get("vuln_type", ""),
                "http_method": finding.get("endpoint", {}).get("method", ""),
                "parameters": finding.get("endpoint", {}).get("parameters", {}),
                "request_details": finding.get("request_details", {})
            },
            business_impact=finding.get("impact", "medium"),
            remediation=finding.get("remediation", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_binary_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize binary analysis finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.BINARY_ANALYSIS,
            finding_type=finding.get("vuln_class", "binary_vulnerability"),
            title=finding.get("description", "Binary Analysis Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.5),
            asset=finding.get("binary_path", ""),
            location={
                "binary": finding.get("binary_path", ""),
                "address": finding.get("address", 0),
                "function": finding.get("affected_functions", []),
                "offset": finding.get("offset", 0)
            },
            evidence={
                "exploit_code": finding.get("exploit_code", ""),
                "proof_of_concept": finding.get("proof_of_concept", ""),
                "disassembly": finding.get("disassembly", "")
            },
            technical_details={
                "vulnerability_type": finding.get("vuln_class", ""),
                "exploitation_technique": finding.get("exploitation_technique", ""),
                "required_conditions": finding.get("required_conditions", []),
                "mitigation_bypass": finding.get("mitigation_bypass", [])
            },
            business_impact=finding.get("business_impact", "high"),
            remediation=finding.get("mitigation_strategies", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_mobile_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize mobile security finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.MOBILE_SECURITY,
            finding_type=finding.get("category", "mobile_vulnerability"),
            title=finding.get("title", "Mobile Security Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.7),
            asset=finding.get("app_path", finding.get("package_name", "")),
            location={
                "app": finding.get("app_path", ""),
                "component": finding.get("component", ""),
                "class": finding.get("class_name", ""),
                "method": finding.get("method_name", "")
            },
            evidence={
                "code_snippet": finding.get("code_snippet", ""),
                "manifest_entry": finding.get("manifest_entry", ""),
                "runtime_behavior": finding.get("runtime_behavior", {})
            },
            technical_details={
                "owasp_category": finding.get("owasp_category", ""),
                "platform": finding.get("platform", ""),
                "api_level": finding.get("api_level", ""),
                "permissions": finding.get("permissions", [])
            },
            business_impact=finding.get("business_impact", "medium"),
            remediation=finding.get("remediation_steps", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_osint_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize OSINT finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.OSINT,
            finding_type=finding.get("type", "intelligence"),
            title=finding.get("title", "OSINT Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "info"),
            confidence=finding.get("confidence", 0.6),
            asset=finding.get("target", ""),
            location={
                "source": finding.get("source", ""),
                "url": finding.get("url", ""),
                "platform": finding.get("platform", "")
            },
            evidence={
                "raw_data": finding.get("raw_data", ""),
                "screenshot": finding.get("screenshot", ""),
                "metadata": finding.get("source_metadata", {})
            },
            technical_details={
                "data_type": finding.get("data_type", ""),
                "collection_method": finding.get("collection_method", ""),
                "reliability": finding.get("reliability", "unknown")
            },
            business_impact=finding.get("business_impact", "low"),
            remediation=finding.get("recommended_actions", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_threat_intel_finding(self, finding_id: str, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize threat intelligence finding"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=FindingSource.THREAT_INTELLIGENCE,
            finding_type=finding.get("threat_type", "threat_indicator"),
            title=finding.get("title", "Threat Intelligence"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "info"),
            confidence=finding.get("confidence", 0.5),
            asset=finding.get("target", ""),
            location={
                "context": finding.get("context", ""),
                "geographic": finding.get("geographic_context", ""),
                "temporal": finding.get("temporal_context", "")
            },
            evidence={
                "indicators": finding.get("indicators", []),
                "attribution": finding.get("attribution", {}),
                "campaign": finding.get("campaign_info", {})
            },
            technical_details={
                "threat_actor": finding.get("threat_actor", ""),
                "ttps": finding.get("ttps", []),
                "iocs": finding.get("iocs", []),
                "kill_chain_phase": finding.get("kill_chain_phase", "")
            },
            business_impact=finding.get("business_impact", "medium"),
            remediation=finding.get("countermeasures", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _normalize_generic_finding(self, finding_id: str, source: FindingSource, finding: Dict[str, Any]) -> UnifiedFinding:
        """Normalize generic finding for unknown sources"""
        return UnifiedFinding(
            finding_id=finding_id,
            source=source,
            finding_type=finding.get("type", "generic_finding"),
            title=finding.get("title", f"{source.value.title()} Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.5),
            asset=finding.get("asset", finding.get("target", "")),
            location=finding.get("location", {}),
            evidence=finding.get("evidence", {}),
            technical_details=finding.get("technical_details", {}),
            business_impact=finding.get("business_impact", "medium"),
            remediation=finding.get("remediation", []),
            timestamps={"discovered": datetime.now()},
            metadata=finding.get("metadata", {})
        )

    async def _calculate_similarity_matrix(self, findings: List[UnifiedFinding]) -> np.ndarray:
        """Calculate similarity matrix between all findings"""
        n_findings = len(findings)
        similarity_matrix = np.zeros((n_findings, n_findings))

        for i in range(n_findings):
            for j in range(i, n_findings):
                if i == j:
                    similarity_matrix[i][j] = 1.0
                else:
                    similarity = await self.similarity_engine.calculate_similarity(findings[i], findings[j])
                    similarity_matrix[i][j] = similarity
                    similarity_matrix[j][i] = similarity  # Symmetric matrix

        return similarity_matrix

    async def _build_vulnerability_graph(self, findings: List[UnifiedFinding],
                                       similarity_matrix: np.ndarray) -> nx.DiGraph:
        """Build directed graph of vulnerability relationships"""
        graph = nx.DiGraph()

        # Add nodes (findings)
        for i, finding in enumerate(findings):
            graph.add_node(i, **asdict(finding))

        # Add edges based on relationships
        threshold = self.config.get("correlation_threshold", 0.7)

        for i in range(len(findings)):
            for j in range(len(findings)):
                if i != j and similarity_matrix[i][j] > threshold:
                    # Determine relationship type
                    relationship = await self._determine_relationship(findings[i], findings[j])

                    if relationship["type"] != "none":
                        graph.add_edge(i, j,
                                     relationship_type=relationship["type"],
                                     confidence=relationship["confidence"],
                                     explanation=relationship["explanation"])

        return graph

    async def _determine_relationship(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> Dict[str, Any]:
        """Determine relationship type between two findings"""
        # Asset-based correlation
        if finding1.asset == finding2.asset and finding1.asset:
            if finding1.source != finding2.source:
                return {
                    "type": "confirmation",
                    "confidence": 0.8,
                    "explanation": f"Same asset ({finding1.asset}) affected by different analysis methods"
                }

        # Location-based correlation
        location_similarity = await self._calculate_location_similarity(finding1.location, finding2.location)
        if location_similarity > 0.8:
            return {
                "type": "direct_chain",
                "confidence": location_similarity,
                "explanation": "Findings in same or closely related locations"
            }

        # Attack chain detection
        if await self._is_attack_chain(finding1, finding2):
            return {
                "type": "attack_path",
                "confidence": 0.9,
                "explanation": "Findings form potential attack path"
            }

        # Amplification detection
        if await self._is_amplification(finding1, finding2):
            return {
                "type": "amplification",
                "confidence": 0.7,
                "explanation": "Combined findings increase overall risk"
            }

        return {"type": "none", "confidence": 0.0, "explanation": "No significant relationship detected"}

    async def _identify_vulnerability_chains(self, vulnerability_graph: nx.DiGraph) -> List[VulnerabilityChain]:
        """Identify vulnerability chains from the correlation graph"""
        chains = []

        # Find strongly connected components and paths
        try:
            # Find all simple paths of length 2-5 (reasonable chain lengths)
            for source in vulnerability_graph.nodes():
                for target in vulnerability_graph.nodes():
                    if source != target:
                        try:
                            paths = list(nx.all_simple_paths(
                                vulnerability_graph, source, target, cutoff=5
                            ))

                            for path in paths:
                                if len(path) >= 2:  # At least 2 findings in chain
                                    chain = await self._create_vulnerability_chain(vulnerability_graph, path)
                                    if chain and chain.chaining_confidence > 0.6:
                                        chains.append(chain)

                        except nx.NetworkXNoPath:
                            continue

            # Remove duplicate and low-confidence chains
            chains = await self._deduplicate_chains(chains)
            chains.sort(key=lambda x: x.chaining_confidence, reverse=True)

        except Exception as e:
            logging.error(f"Error identifying vulnerability chains: {e}")

        return chains[:20]  # Limit to top 20 chains

    async def _create_vulnerability_chain(self, graph: nx.DiGraph, path: List[int]) -> Optional[VulnerabilityChain]:
        """Create vulnerability chain from graph path"""
        try:
            # Get findings from path
            chain_findings = []
            for node_id in path:
                node_data = graph.nodes[node_id]
                # Convert back to UnifiedFinding
                finding = UnifiedFinding(**{k: v for k, v in node_data.items()
                                          if k in UnifiedFinding.__annotations__})
                chain_findings.append(finding)

            # Calculate chain properties
            attack_path = await self._generate_attack_path_description(chain_findings)
            combined_severity = await self._calculate_combined_severity(chain_findings)
            exploit_complexity = await self._assess_exploit_complexity(chain_findings)
            chaining_confidence = await self._calculate_chaining_confidence(graph, path)
            impact_amplification = await self._calculate_impact_amplification(chain_findings)

            chain_id = f"chain_{hashlib.md5(''.join(f.finding_id for f in chain_findings).encode()).hexdigest()[:8]}"

            return VulnerabilityChain(
                chain_id=chain_id,
                findings=chain_findings,
                attack_path=attack_path,
                combined_severity=combined_severity,
                exploit_complexity=exploit_complexity,
                chaining_confidence=chaining_confidence,
                business_impact_amplification=impact_amplification,
                proof_of_concept=await self._generate_chain_poc(chain_findings),
                mitigation_strategy=await self._generate_chain_mitigation(chain_findings)
            )

        except Exception as e:
            logging.error(f"Error creating vulnerability chain: {e}")
            return None

    async def _generate_attack_scenarios(self, vulnerability_chains: List[VulnerabilityChain]) -> List[AttackScenario]:
        """Generate comprehensive attack scenarios from vulnerability chains"""
        scenarios = []

        # Group chains by target/asset
        chains_by_asset = defaultdict(list)
        for chain in vulnerability_chains:
            # Get primary asset from chain
            primary_asset = chain.findings[0].asset if chain.findings else "unknown"
            chains_by_asset[primary_asset].append(chain)

        # Create scenarios for each asset group
        scenario_counter = 1
        for asset, asset_chains in chains_by_asset.items():
            if len(asset_chains) >= 1:  # At least one chain required
                scenario = await self._create_attack_scenario(f"scenario_{scenario_counter}", asset, asset_chains)
                if scenario:
                    scenarios.append(scenario)
                    scenario_counter += 1

        # Cross-asset scenarios (advanced attacks)
        if len(chains_by_asset) > 1:
            cross_asset_scenario = await self._create_cross_asset_scenario(chains_by_asset)
            if cross_asset_scenario:
                scenarios.append(cross_asset_scenario)

        return scenarios

    async def _create_attack_scenario(self, scenario_id: str, asset: str,
                                    chains: List[VulnerabilityChain]) -> Optional[AttackScenario]:
        """Create attack scenario for specific asset"""
        try:
            # Sort chains by confidence and severity
            chains.sort(key=lambda x: (x.chaining_confidence,
                                     {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.combined_severity, 0)),
                       reverse=True)

            # Generate scenario details
            scenario_name = f"Multi-Vector Attack on {asset}"
            description = await self._generate_scenario_description(asset, chains)
            success_probability = await self._calculate_scenario_success_probability(chains)
            potential_impact = await self._assess_scenario_impact(chains)
            timeline_estimate = await self._estimate_attack_timeline(chains)
            detection_difficulty = await self._assess_detection_difficulty(chains)
            mitigation_cost = await self._estimate_mitigation_cost(chains)

            # Identify required conditions
            required_conditions = []
            for chain in chains:
                for finding in chain.findings:
                    if finding.source == FindingSource.DAST and "authentication" in finding.technical_details:
                        required_conditions.append("Network access to target")
                    elif finding.source == FindingSource.BINARY_ANALYSIS:
                        required_conditions.append("Local access or code execution")
                    elif finding.source == FindingSource.MOBILE_SECURITY:
                        required_conditions.append("Mobile app installation")

            required_conditions = list(set(required_conditions))  # Remove duplicates

            return AttackScenario(
                scenario_id=scenario_id,
                name=scenario_name,
                description=description,
                attack_chains=chains,
                required_conditions=required_conditions,
                success_probability=success_probability,
                potential_impact=potential_impact,
                timeline_estimate=timeline_estimate,
                detection_difficulty=detection_difficulty,
                mitigation_cost=mitigation_cost
            )

        except Exception as e:
            logging.error(f"Error creating attack scenario: {e}")
            return None

    async def _extract_intelligence_insights(self, findings: List[UnifiedFinding],
                                           chains: List[VulnerabilityChain],
                                           scenarios: List[AttackScenario]) -> List[IntelligenceInsight]:
        """Extract high-level intelligence insights"""
        insights = []

        # Security posture insight
        security_posture = await self._analyze_security_posture(findings)
        if security_posture:
            insights.append(security_posture)

        # Attack surface insight
        attack_surface = await self._analyze_attack_surface(findings, chains)
        if attack_surface:
            insights.append(attack_surface)

        # Risk concentration insight
        risk_concentration = await self._analyze_risk_concentration(findings, scenarios)
        if risk_concentration:
            insights.append(risk_concentration)

        # Mitigation priorities insight
        mitigation_priorities = await self._analyze_mitigation_priorities(chains, scenarios)
        if mitigation_priorities:
            insights.append(mitigation_priorities)

        # Threat landscape insight
        threat_landscape = await self._analyze_threat_landscape(findings)
        if threat_landscape:
            insights.append(threat_landscape)

        return insights

    async def _conduct_risk_assessment(self, findings: List[UnifiedFinding],
                                     chains: List[VulnerabilityChain],
                                     scenarios: List[AttackScenario]) -> Dict[str, Any]:
        """Conduct comprehensive risk assessment"""
        assessment = {
            "overall_risk_score": 0.0,
            "risk_level": RiskLevel.LOW.value,
            "critical_findings": 0,
            "high_risk_chains": 0,
            "exploitable_scenarios": 0,
            "business_impact_areas": [],
            "immediate_actions_required": [],
            "strategic_recommendations": [],
            "risk_factors": {},
            "mitigation_roadmap": {}
        }

        # Count findings by severity
        severity_counts = Counter(f.severity for f in findings)
        assessment["critical_findings"] = severity_counts.get("critical", 0)

        # High-risk chains
        high_risk_chains = [c for c in chains if c.chaining_confidence > 0.8]
        assessment["high_risk_chains"] = len(high_risk_chains)

        # Exploitable scenarios
        exploitable_scenarios = [s for s in scenarios if s.success_probability > 0.7]
        assessment["exploitable_scenarios"] = len(exploitable_scenarios)

        # Calculate overall risk score
        risk_score = 0.0
        risk_score += min(assessment["critical_findings"] * 0.3, 0.5)
        risk_score += min(assessment["high_risk_chains"] * 0.2, 0.3)
        risk_score += min(assessment["exploitable_scenarios"] * 0.15, 0.2)

        assessment["overall_risk_score"] = min(risk_score, 1.0)

        # Determine risk level
        if risk_score > 0.8:
            assessment["risk_level"] = RiskLevel.CRITICAL.value
        elif risk_score > 0.6:
            assessment["risk_level"] = RiskLevel.HIGH.value
        elif risk_score > 0.4:
            assessment["risk_level"] = RiskLevel.MEDIUM.value
        else:
            assessment["risk_level"] = RiskLevel.LOW.value

        # Business impact areas
        impact_areas = set()
        for scenario in scenarios:
            for impact_area, impact_level in scenario.potential_impact.items():
                if impact_level in ["high", "critical"]:
                    impact_areas.add(impact_area)
        assessment["business_impact_areas"] = list(impact_areas)

        # Immediate actions
        if assessment["critical_findings"] > 0:
            assessment["immediate_actions_required"].append("Address critical vulnerabilities immediately")
        if assessment["exploitable_scenarios"] > 0:
            assessment["immediate_actions_required"].append("Implement emergency mitigations for exploitable scenarios")

        return assessment

    # Helper methods (simplified implementations)
    async def _calculate_location_similarity(self, loc1: Dict[str, Any], loc2: Dict[str, Any]) -> float:
        """Calculate similarity between two locations"""
        if loc1.get("file") and loc2.get("file") and loc1["file"] == loc2["file"]:
            return 0.9
        elif loc1.get("url") and loc2.get("url") and loc1["url"] == loc2["url"]:
            return 0.9
        return 0.0

    async def _is_attack_chain(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        """Check if two findings form an attack chain"""
        # Simple heuristic: OSINT -> DAST -> SAST chain
        chain_patterns = [
            (FindingSource.OSINT, FindingSource.DAST),
            (FindingSource.DAST, FindingSource.SAST),
            (FindingSource.SAST, FindingSource.BINARY_ANALYSIS)
        ]

        return (finding1.source, finding2.source) in chain_patterns

    async def _is_amplification(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        """Check if two findings amplify each other"""
        # Check for known amplification patterns
        amplification_patterns = [
            ("authentication_bypass", "privilege_escalation"),
            ("sql_injection", "file_inclusion"),
            ("xss", "csrf")
        ]

        return any((pattern[0] in finding1.finding_type and pattern[1] in finding2.finding_type) or
                  (pattern[1] in finding1.finding_type and pattern[0] in finding2.finding_type)
                  for pattern in amplification_patterns)

    async def _deduplicate_chains(self, chains: List[VulnerabilityChain]) -> List[VulnerabilityChain]:
        """Remove duplicate vulnerability chains"""
        unique_chains = []
        seen_chain_hashes = set()

        for chain in chains:
            # Create hash of findings in chain
            finding_ids = sorted([f.finding_id for f in chain.findings])
            chain_hash = hashlib.md5(''.join(finding_ids).encode()).hexdigest()

            if chain_hash not in seen_chain_hashes:
                seen_chain_hashes.add(chain_hash)
                unique_chains.append(chain)

        return unique_chains

    async def _calculate_correlation_metrics(self, findings: List[UnifiedFinding],
                                           similarity_matrix: np.ndarray,
                                           chains: List[VulnerabilityChain]) -> Dict[str, Any]:
        """Calculate various correlation metrics"""
        metrics = {
            "total_correlations": 0,
            "correlation_density": 0.0,
            "average_similarity": 0.0,
            "cross_modal_correlations": 0,
            "chain_coverage": 0.0,
            "confidence_distribution": {}
        }

        if len(findings) > 1:
            # Total correlations above threshold
            threshold = self.config.get("correlation_threshold", 0.7)
            correlations = np.sum(similarity_matrix > threshold) - len(findings)  # Exclude diagonal
            metrics["total_correlations"] = int(correlations / 2)  # Undirected graph

            # Correlation density
            max_possible = (len(findings) * (len(findings) - 1)) / 2
            metrics["correlation_density"] = correlations / (2 * max_possible) if max_possible > 0 else 0.0

            # Average similarity
            upper_triangle = similarity_matrix[np.triu_indices(len(findings), k=1)]
            metrics["average_similarity"] = float(np.mean(upper_triangle))

            # Cross-modal correlations
            cross_modal = 0
            for i in range(len(findings)):
                for j in range(i+1, len(findings)):
                    if (findings[i].source != findings[j].source and
                        similarity_matrix[i][j] > threshold):
                        cross_modal += 1
            metrics["cross_modal_correlations"] = cross_modal

            # Chain coverage
            findings_in_chains = set()
            for chain in chains:
                for finding in chain.findings:
                    findings_in_chains.add(finding.finding_id)
            metrics["chain_coverage"] = len(findings_in_chains) / len(findings)

        return metrics

    # Placeholder methods for complex analysis
    async def _generate_attack_path_description(self, findings: List[UnifiedFinding]) -> List[str]:
        """Generate attack path description"""
        return [f"Step {i+1}: {f.title}" for i, f in enumerate(findings)]

    async def _calculate_combined_severity(self, findings: List[UnifiedFinding]) -> str:
        """Calculate combined severity of findings chain"""
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_score = max(severity_scores.get(f.severity, 1) for f in findings)

        for score, severity in severity_scores.items():
            if severity == max_score:
                return score
        return "medium"

    async def _assess_exploit_complexity(self, findings: List[UnifiedFinding]) -> str:
        """Assess exploit complexity"""
        return "medium"  # Simplified

    async def _calculate_chaining_confidence(self, graph: nx.DiGraph, path: List[int]) -> float:
        """Calculate confidence in vulnerability chaining"""
        if len(path) < 2:
            return 0.0

        confidences = []
        for i in range(len(path) - 1):
            edge_data = graph.get_edge_data(path[i], path[i+1], {})
            confidences.append(edge_data.get("confidence", 0.5))

        return np.mean(confidences) if confidences else 0.0

    async def _calculate_impact_amplification(self, findings: List[UnifiedFinding]) -> float:
        """Calculate business impact amplification"""
        return 1.5  # Simplified multiplier

    async def _generate_chain_poc(self, findings: List[UnifiedFinding]) -> Optional[str]:
        """Generate proof of concept for chain"""
        return None  # Would implement PoC generation

    async def _generate_chain_mitigation(self, findings: List[UnifiedFinding]) -> List[str]:
        """Generate mitigation strategy for chain"""
        mitigations = []
        for finding in findings:
            mitigations.extend(finding.remediation)
        return list(set(mitigations))  # Remove duplicates

    async def _create_cross_asset_scenario(self, chains_by_asset: Dict[str, List[VulnerabilityChain]]) -> Optional[AttackScenario]:
        """Create cross-asset attack scenario"""
        return None  # Would implement cross-asset scenario creation

    async def _generate_scenario_description(self, asset: str, chains: List[VulnerabilityChain]) -> str:
        """Generate attack scenario description"""
        return f"Multi-vector attack targeting {asset} using {len(chains)} vulnerability chains"

    async def _calculate_scenario_success_probability(self, chains: List[VulnerabilityChain]) -> float:
        """Calculate attack scenario success probability"""
        if not chains:
            return 0.0
        return max(chain.chaining_confidence for chain in chains)

    async def _assess_scenario_impact(self, chains: List[VulnerabilityChain]) -> Dict[str, Any]:
        """Assess potential impact of attack scenario"""
        return {
            "confidentiality": "high",
            "integrity": "medium",
            "availability": "low",
            "financial": "medium",
            "reputation": "high"
        }

    async def _estimate_attack_timeline(self, chains: List[VulnerabilityChain]) -> str:
        """Estimate attack timeline"""
        return "hours to days"

    async def _assess_detection_difficulty(self, chains: List[VulnerabilityChain]) -> str:
        """Assess detection difficulty"""
        return "medium"

    async def _estimate_mitigation_cost(self, chains: List[VulnerabilityChain]) -> str:
        """Estimate mitigation cost"""
        return "medium"

    async def _analyze_security_posture(self, findings: List[UnifiedFinding]) -> Optional[IntelligenceInsight]:
        """Analyze overall security posture"""
        return IntelligenceInsight(
            insight_id="security_posture_001",
            insight_type="security_posture",
            confidence=0.8,
            description=f"Analysis of {len(findings)} findings reveals mixed security posture",
            supporting_evidence=[f.finding_id for f in findings[:5]],
            actionable_recommendations=["Implement security review process", "Enhance testing coverage"],
            business_priority="high",
            technical_complexity="medium"
        )

    async def _analyze_attack_surface(self, findings: List[UnifiedFinding],
                                    chains: List[VulnerabilityChain]) -> Optional[IntelligenceInsight]:
        """Analyze attack surface"""
        return None  # Would implement attack surface analysis

    async def _analyze_risk_concentration(self, findings: List[UnifiedFinding],
                                        scenarios: List[AttackScenario]) -> Optional[IntelligenceInsight]:
        """Analyze risk concentration"""
        return None

    async def _analyze_mitigation_priorities(self, chains: List[VulnerabilityChain],
                                           scenarios: List[AttackScenario]) -> Optional[IntelligenceInsight]:
        """Analyze mitigation priorities"""
        return None

    async def _analyze_threat_landscape(self, findings: List[UnifiedFinding]) -> Optional[IntelligenceInsight]:
        """Analyze threat landscape"""
        return None


class FindingSimilarityEngine:
    """Engine for calculating similarity between findings"""

    async def calculate_similarity(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> float:
        """Calculate overall similarity between two findings"""
        similarity_components = []

        # Asset similarity
        asset_sim = self._calculate_asset_similarity(finding1.asset, finding2.asset)
        similarity_components.append(asset_sim * 0.3)

        # Type similarity
        type_sim = self._calculate_type_similarity(finding1.finding_type, finding2.finding_type)
        similarity_components.append(type_sim * 0.2)

        # Location similarity
        location_sim = await self._calculate_location_similarity(finding1.location, finding2.location)
        similarity_components.append(location_sim * 0.3)

        # Description similarity
        desc_sim = self._calculate_text_similarity(finding1.description, finding2.description)
        similarity_components.append(desc_sim * 0.2)

        return sum(similarity_components)

    def _calculate_asset_similarity(self, asset1: str, asset2: str) -> float:
        """Calculate asset similarity"""
        if asset1 == asset2 and asset1:
            return 1.0
        elif asset1 and asset2 and (asset1 in asset2 or asset2 in asset1):
            return 0.7
        return 0.0

    def _calculate_type_similarity(self, type1: str, type2: str) -> float:
        """Calculate finding type similarity"""
        if type1 == type2:
            return 1.0

        # Define related types
        related_types = {
            "sql_injection": ["database_injection", "sqli"],
            "xss": ["cross_site_scripting", "script_injection"],
            "buffer_overflow": ["memory_corruption", "stack_overflow"]
        }

        for base_type, related in related_types.items():
            if (type1 == base_type and type2 in related) or (type2 == base_type and type1 in related):
                return 0.8

        return 0.0

    async def _calculate_location_similarity(self, loc1: Dict[str, Any], loc2: Dict[str, Any]) -> float:
        """Calculate location similarity"""
        if not loc1 or not loc2:
            return 0.0

        # File-based similarity
        if loc1.get("file") and loc2.get("file"):
            if loc1["file"] == loc2["file"]:
                return 1.0
            elif any(common in loc1["file"] and common in loc2["file"]
                    for common in ["/", ".", "-", "_"]):
                return 0.5

        # URL-based similarity
        if loc1.get("url") and loc2.get("url"):
            if loc1["url"] == loc2["url"]:
                return 1.0

        return 0.0

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity using simple metrics"""
        if not text1 or not text2:
            return 0.0

        # Simple word overlap
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        return len(intersection) / len(union) if union else 0.0


class VulnerabilityGraphAnalyzer:
    """Analyzer for vulnerability relationship graphs"""
    pass


class AttackPathFinder:
    """Finder for attack paths through vulnerabilities"""
    pass


class RiskCalculator:
    """Calculator for various risk metrics"""
    pass


class CorrelationNeuralNetwork(nn.Module):
    """Neural network for finding correlation"""

    def __init__(self, input_dim=100, hidden_dim=64):
        super().__init__()
        if ML_AVAILABLE:
            self.network = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, 1),
                nn.Sigmoid()
            )

    def forward(self, x):
        if ML_AVAILABLE:
            return self.network(x)
        return torch.zeros(x.shape[0], 1)


class AnomalyDetector:
    """Anomaly detector for finding outliers"""
    pass


class ImpactPredictor:
    """Predictor for business impact of vulnerabilities"""
    pass


class VulnerabilityTaxonomy:
    """Taxonomy of vulnerability types and relationships"""
    pass


class AttackPatternDatabase:
    """Database of known attack patterns"""
    pass


class CorrelationRuleEngine:
    """Rule engine for correlation logic"""
    pass


# Factory function for easy instantiation
class UnifiedIntelligenceLayer:
    """
    Main unified intelligence layer class that provides high-level interface
    for cross-modal correlation and intelligence analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.correlation_engine = CrossModalCorrelationEngine(self.config)

    async def correlate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate findings from multiple sources"""
        # Convert simple findings list to the expected format
        findings_by_source = {FindingSource.SAST: findings}
        return await self.correlation_engine.correlate_findings(findings_by_source)

    async def analyze_attack_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze potential attack paths"""
        correlation_results = await self.correlate_findings(findings)
        return correlation_results.get('attack_scenarios', [])

    async def get_intelligence_insights(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get high-level intelligence insights"""
        correlation_results = await self.correlate_findings(findings)
        return correlation_results.get('intelligence_insights', [])

def create_unified_intelligence_layer(config: Optional[Dict[str, Any]] = None) -> CrossModalCorrelationEngine:
    """Factory function to create unified intelligence layer"""
    default_config = {
        "correlation_threshold": 0.7,
        "max_chains": 20,
        "min_chain_confidence": 0.6,
        "enable_ml_correlation": ML_AVAILABLE,
        "enable_graph_analysis": True
    }

    final_config = {**default_config, **(config or {})}
    return CrossModalCorrelationEngine(final_config)


if __name__ == "__main__":
    # Example usage
    async def main():
        # Create intelligence layer
        intelligence_layer = create_unified_intelligence_layer()

        # Mock findings from different sources
        mock_findings = {
            FindingSource.SAST: [
                {
                    "id": "sast_001",
                    "type": "sql_injection",
                    "severity": "high",
                    "confidence": 0.8,
                    "file_path": "/app/user.py",
                    "line_number": 42,
                    "description": "SQL injection in login function"
                }
            ],
            FindingSource.DAST: [
                {
                    "vuln_type": "sql_injection",
                    "severity": "high",
                    "confidence": 0.9,
                    "endpoint": {"url": "https://app.com/login", "method": "POST"},
                    "payload": "' OR '1'='1",
                    "description": "Confirmed SQL injection"
                }
            ],
            FindingSource.OSINT: [
                {
                    "type": "exposed_credentials",
                    "severity": "medium",
                    "confidence": 0.7,
                    "target": "app.com",
                    "description": "Database credentials found in GitHub"
                }
            ]
        }

        # Perform correlation
        results = await intelligence_layer.correlate_findings(mock_findings)

        print(f"Correlation Analysis Results:")
        print(f"  Total findings processed: {results['total_findings']}")
        print(f"  Vulnerability chains found: {len(results['vulnerability_chains'])}")
        print(f"  Attack scenarios generated: {len(results['attack_scenarios'])}")
        print(f"  Intelligence insights: {len(results['intelligence_insights'])}")
        print(f"  Overall risk level: {results['risk_assessment']['risk_level']}")

    asyncio.run(main())