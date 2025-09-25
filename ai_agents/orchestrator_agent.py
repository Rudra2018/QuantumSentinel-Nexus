#!/usr/bin/env python3
"""
🧠 ORCHESTRATOR AGENT - DECISION ENGINE
=====================================
Master AI agent that coordinates all specialized security testing agents
and makes strategic decisions about testing approaches.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path

class AgentStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"

@dataclass
class AgentTask:
    """Represents a task assigned to a specialized agent"""
    task_id: str
    agent_type: str
    target: str
    parameters: Dict[str, Any]
    priority: int
    created_at: datetime
    dependencies: List[str]
    status: AgentStatus = AgentStatus.IDLE
    results: Optional[Dict[str, Any]] = None
    confidence_score: Optional[float] = None
    error_message: Optional[str] = None

@dataclass
class VulnerabilityContext:
    """Context about discovered vulnerabilities for decision making"""
    vuln_type: str
    severity: str
    asset_type: str
    business_impact: str
    confidence: float
    exploitation_complexity: str
    attack_vector: str
    requires_followup: bool = False
    suggested_agents: List[str] = None

class OrchestratorAgent:
    """
    Master orchestrator agent that:
    1. Analyzes targets and creates execution strategies
    2. Coordinates specialized agents based on findings
    3. Makes real-time decisions about testing depth and focus
    4. Learns from results to improve future decisions
    """

    def __init__(self, config_path: str = "config/agent_orchestrator.yaml"):
        self.session_id = f"ORG-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.config = self.load_config(config_path)

        # Agent registry and status tracking
        self.specialized_agents = {}
        self.active_tasks = {}
        self.completed_tasks = {}
        self.knowledge_graph = {}

        # Decision engine components
        self.strategy_engine = StrategyEngine()
        self.priority_manager = PriorityManager()
        self.resource_allocator = ResourceAllocator()

        # Learning and adaptation
        self.learning_engine = LearningEngine()
        self.performance_metrics = {}

        self.setup_logging()

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load orchestrator configuration"""
        # Implementation for loading YAML config
        return {
            "max_concurrent_agents": 10,
            "resource_limits": {"memory": "8GB", "cpu": "80%"},
            "learning_enabled": True,
            "auto_adaptation": True,
            "decision_threshold": 0.7
        }

    async def analyze_target(self, target: str, scope: List[str]) -> Dict[str, Any]:
        """
        Analyze target to determine optimal testing strategy
        """
        analysis = {
            "target": target,
            "scope": scope,
            "asset_types": await self.identify_asset_types(target),
            "attack_surface": await self.map_attack_surface(target),
            "technology_stack": await self.detect_technologies(target),
            "business_context": await self.analyze_business_context(target),
            "risk_profile": await self.assess_risk_profile(target)
        }

        # Generate strategic testing approach
        strategy = await self.strategy_engine.create_strategy(analysis)

        return {
            "analysis": analysis,
            "strategy": strategy,
            "recommended_agents": strategy.get("agent_sequence", []),
            "estimated_duration": strategy.get("duration", "unknown"),
            "resource_requirements": strategy.get("resources", {})
        }

    async def create_execution_plan(self, target_analysis: Dict[str, Any]) -> List[AgentTask]:
        """
        Create detailed execution plan with agent tasks
        """
        strategy = target_analysis["strategy"]
        tasks = []

        # Phase 1: Reconnaissance and OSINT (parallel execution)
        recon_tasks = [
            AgentTask(
                task_id=f"recon_passive_{self.session_id}",
                agent_type="recon_agent",
                target=target_analysis["analysis"]["target"],
                parameters={
                    "mode": "passive",
                    "tools": ["subfinder", "amass", "shodan"],
                    "depth": "comprehensive"
                },
                priority=1,
                created_at=datetime.now(),
                dependencies=[]
            ),
            AgentTask(
                task_id=f"osint_deep_{self.session_id}",
                agent_type="osint_agent",
                target=target_analysis["analysis"]["target"],
                parameters={
                    "github_dorks": True,
                    "breach_check": True,
                    "tech_intelligence": True,
                    "credential_exposure": True
                },
                priority=1,
                created_at=datetime.now(),
                dependencies=[]
            )
        ]
        tasks.extend(recon_tasks)

        # Phase 2: Active reconnaissance (depends on Phase 1)
        active_recon_task = AgentTask(
            task_id=f"recon_active_{self.session_id}",
            agent_type="recon_agent",
            target=target_analysis["analysis"]["target"],
            parameters={
                "mode": "active",
                "tools": ["httpx", "nuclei", "katana"],
                "use_discovered_subdomains": True
            },
            priority=2,
            created_at=datetime.now(),
            dependencies=[task.task_id for task in recon_tasks]
        )
        tasks.append(active_recon_task)

        # Phase 3: Specialized testing based on discovered assets
        if "web" in target_analysis["analysis"]["asset_types"]:
            web_task = AgentTask(
                task_id=f"sast_web_{self.session_id}",
                agent_type="sast_agent",
                target=target_analysis["analysis"]["target"],
                parameters={
                    "scan_type": "web_application",
                    "frameworks": target_analysis["analysis"]["technology_stack"],
                    "depth": "semantic_analysis"
                },
                priority=3,
                created_at=datetime.now(),
                dependencies=[active_recon_task.task_id]
            )
            tasks.append(web_task)

            dast_task = AgentTask(
                task_id=f"dast_web_{self.session_id}",
                agent_type="dast_agent",
                target=target_analysis["analysis"]["target"],
                parameters={
                    "crawling_mode": "intelligent",
                    "authentication": "auto_detect",
                    "business_logic": True,
                    "api_testing": True
                },
                priority=3,
                created_at=datetime.now(),
                dependencies=[active_recon_task.task_id]
            )
            tasks.append(dast_task)

        if "mobile" in target_analysis["analysis"]["asset_types"]:
            mobile_task = AgentTask(
                task_id=f"mobile_security_{self.session_id}",
                agent_type="mobile_agent",
                target=target_analysis["analysis"]["target"],
                parameters={
                    "platforms": ["android", "ios"],
                    "analysis_depth": "comprehensive",
                    "runtime_testing": True,
                    "binary_analysis": True
                },
                priority=3,
                created_at=datetime.now(),
                dependencies=[active_recon_task.task_id]
            )
            tasks.append(mobile_task)

        # Phase 4: Cross-correlation and deep analysis
        ml_analysis_task = AgentTask(
            task_id=f"ml_threat_intel_{self.session_id}",
            agent_type="ml_threat_intelligence_agent",
            target=target_analysis["analysis"]["target"],
            parameters={
                "correlate_findings": True,
                "predict_attack_paths": True,
                "zero_day_detection": True,
                "business_logic_analysis": True
            },
            priority=4,
            created_at=datetime.now(),
            dependencies=[task.task_id for task in tasks if task.priority == 3]
        )
        tasks.append(ml_analysis_task)

        # Phase 5: Report synthesis
        report_task = AgentTask(
            task_id=f"report_synthesis_{self.session_id}",
            agent_type="report_synthesis_agent",
            target=target_analysis["analysis"]["target"],
            parameters={
                "format": "comprehensive",
                "include_attack_chains": True,
                "executive_summary": True,
                "technical_details": True,
                "remediation_priorities": True
            },
            priority=5,
            created_at=datetime.now(),
            dependencies=[ml_analysis_task.task_id]
        )
        tasks.append(report_task)

        return tasks

    async def execute_orchestration(self, execution_plan: List[AgentTask]) -> Dict[str, Any]:
        """
        Execute the orchestrated security testing plan
        """
        execution_results = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "total_tasks": len(execution_plan),
            "completed_tasks": 0,
            "failed_tasks": 0,
            "findings": [],
            "performance_metrics": {}
        }

        # Priority-based execution with dependency resolution
        pending_tasks = {task.task_id: task for task in execution_plan}

        while pending_tasks:
            # Find ready tasks (dependencies satisfied)
            ready_tasks = []
            for task_id, task in pending_tasks.items():
                if all(dep_id in self.completed_tasks for dep_id in task.dependencies):
                    ready_tasks.append(task)

            if not ready_tasks:
                logging.error("Deadlock detected in task dependencies")
                break

            # Execute ready tasks (parallel where possible)
            await self.execute_task_batch(ready_tasks)

            # Update pending tasks
            for task in ready_tasks:
                if task.status == AgentStatus.COMPLETED:
                    self.completed_tasks[task.task_id] = task
                    execution_results["completed_tasks"] += 1
                elif task.status == AgentStatus.FAILED:
                    execution_results["failed_tasks"] += 1

                # Remove from pending
                pending_tasks.pop(task.task_id, None)

            # Adaptive decision making - adjust plan based on results
            await self.adapt_execution_plan(pending_tasks)

        execution_results["end_time"] = datetime.now().isoformat()
        execution_results["findings"] = await self.consolidate_findings()

        # Learn from this execution
        await self.learning_engine.learn_from_execution(execution_results)

        return execution_results

    async def execute_task_batch(self, tasks: List[AgentTask]) -> None:
        """
        Execute a batch of tasks concurrently
        """
        semaphore = asyncio.Semaphore(self.config["max_concurrent_agents"])

        async def execute_single_task(task: AgentTask):
            async with semaphore:
                try:
                    task.status = AgentStatus.ACTIVE

                    # Dispatch to appropriate specialized agent
                    agent = self.get_agent(task.agent_type)
                    results = await agent.execute(task)

                    task.results = results
                    task.confidence_score = results.get("confidence", 0.0)
                    task.status = AgentStatus.COMPLETED

                    # Real-time decision making based on results
                    await self.process_task_results(task)

                except Exception as e:
                    task.status = AgentStatus.FAILED
                    task.error_message = str(e)
                    logging.error(f"Task {task.task_id} failed: {e}")

        await asyncio.gather(*[execute_single_task(task) for task in tasks])

    async def process_task_results(self, task: AgentTask) -> None:
        """
        Process results from specialized agents and make decisions
        """
        if not task.results:
            return

        # Extract vulnerabilities
        vulnerabilities = task.results.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            vuln_context = VulnerabilityContext(
                vuln_type=vuln.get("type"),
                severity=vuln.get("severity"),
                asset_type=vuln.get("asset_type"),
                business_impact=vuln.get("business_impact", "unknown"),
                confidence=vuln.get("confidence", 0.0),
                exploitation_complexity=vuln.get("complexity", "unknown"),
                attack_vector=vuln.get("attack_vector", "unknown")
            )

            # Decision engine: Should we trigger additional testing?
            additional_tasks = await self.decide_additional_testing(vuln_context, task)

            # Add high-priority follow-up tasks
            for additional_task in additional_tasks:
                await self.inject_task(additional_task)

    async def decide_additional_testing(self, vuln_context: VulnerabilityContext,
                                      origin_task: AgentTask) -> List[AgentTask]:
        """
        AI-driven decision making for additional testing based on findings
        """
        additional_tasks = []

        # High-severity findings trigger deeper analysis
        if vuln_context.severity in ["critical", "high"] and vuln_context.confidence > 0.8:

            # SQL injection found -> trigger advanced SQLMap testing
            if vuln_context.vuln_type == "sql_injection":
                exploitation_task = AgentTask(
                    task_id=f"exploit_sqli_{datetime.now().timestamp()}",
                    agent_type="exploitation_agent",
                    target=origin_task.target,
                    parameters={
                        "vulnerability": vuln_context,
                        "exploitation_type": "sql_injection",
                        "proof_of_concept": True,
                        "data_extraction": True
                    },
                    priority=6,  # High priority
                    created_at=datetime.now(),
                    dependencies=[origin_task.task_id]
                )
                additional_tasks.append(exploitation_task)

            # XSS found -> trigger comprehensive XSS validation
            elif vuln_context.vuln_type == "xss":
                xss_validation_task = AgentTask(
                    task_id=f"validate_xss_{datetime.now().timestamp()}",
                    agent_type="dast_agent",
                    target=origin_task.target,
                    parameters={
                        "focus": "xss_validation",
                        "payloads": "comprehensive",
                        "context_aware": True,
                        "bypass_filters": True
                    },
                    priority=6,
                    created_at=datetime.now(),
                    dependencies=[origin_task.task_id]
                )
                additional_tasks.append(xss_validation_task)

            # Binary vulnerability found -> trigger reverse engineering
            elif vuln_context.asset_type == "binary":
                reverse_eng_task = AgentTask(
                    task_id=f"reverse_eng_{datetime.now().timestamp()}",
                    agent_type="binary_analysis_agent",
                    target=origin_task.target,
                    parameters={
                        "analysis_type": "deep_reverse_engineering",
                        "vulnerability_focus": vuln_context.vuln_type,
                        "exploit_development": True,
                        "symbolic_execution": True
                    },
                    priority=6,
                    created_at=datetime.now(),
                    dependencies=[origin_task.task_id]
                )
                additional_tasks.append(reverse_eng_task)

        return additional_tasks

    async def adapt_execution_plan(self, pending_tasks: Dict[str, AgentTask]) -> None:
        """
        Adaptive execution - modify plan based on real-time results
        """
        # Analyze current findings
        current_findings = await self.get_current_findings()

        # If we're finding many vulnerabilities, increase testing depth
        if len(current_findings) > 10:
            for task in pending_tasks.values():
                if task.agent_type in ["dast_agent", "sast_agent"]:
                    task.parameters["depth"] = "comprehensive"
                    task.parameters["additional_checks"] = True

        # If findings are low-confidence, trigger validation agents
        low_confidence_findings = [f for f in current_findings if f.get("confidence", 0) < 0.6]
        if len(low_confidence_findings) > 5:
            validation_task = AgentTask(
                task_id=f"validation_{datetime.now().timestamp()}",
                agent_type="validation_agent",
                target=list(pending_tasks.values())[0].target if pending_tasks else "",
                parameters={
                    "validate_findings": low_confidence_findings,
                    "live_validation": True,
                    "false_positive_reduction": True
                },
                priority=7,
                created_at=datetime.now(),
                dependencies=[]
            )
            pending_tasks[validation_task.task_id] = validation_task

    def get_agent(self, agent_type: str):
        """Get specialized agent instance"""
        # Factory pattern for agent creation
        if agent_type not in self.specialized_agents:
            self.specialized_agents[agent_type] = self.create_agent(agent_type)
        return self.specialized_agents[agent_type]

    def create_agent(self, agent_type: str):
        """Factory method to create specialized agents"""
        from .sast_agent import SASTSpecialistAgent
        from .dast_agent import DASTSpecialistAgent
        from .binary_analysis_agent import BinaryAnalysisAgent
        from .ml_threat_intelligence_agent import MLThreatIntelligenceAgent
        from .report_synthesis_agent import ReportSynthesisAgent

        agent_classes = {
            "sast_agent": SASTSpecialistAgent,
            "dast_agent": DASTSpecialistAgent,
            "binary_analysis_agent": BinaryAnalysisAgent,
            "ml_threat_intelligence_agent": MLThreatIntelligenceAgent,
            "report_synthesis_agent": ReportSynthesisAgent
        }

        agent_class = agent_classes.get(agent_type)
        if agent_class:
            return agent_class(orchestrator=self)
        else:
            raise ValueError(f"Unknown agent type: {agent_type}")

    async def consolidate_findings(self) -> List[Dict[str, Any]]:
        """Consolidate findings from all completed tasks"""
        all_findings = []
        for task in self.completed_tasks.values():
            if task.results and "vulnerabilities" in task.results:
                all_findings.extend(task.results["vulnerabilities"])
        return all_findings

    async def get_current_findings(self) -> List[Dict[str, Any]]:
        """Get current findings from completed tasks"""
        return await self.consolidate_findings()

    async def inject_task(self, task: AgentTask) -> None:
        """Inject a new high-priority task into the execution"""
        self.active_tasks[task.task_id] = task
        logging.info(f"Injected high-priority task: {task.task_id}")

    def setup_logging(self):
        """Setup logging for the orchestrator"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ORCHESTRATOR - %(levelname)s - %(message)s'
        )

    # Placeholder methods for core functionality
    async def identify_asset_types(self, target: str) -> List[str]:
        """Identify types of assets (web, mobile, binary, etc.)"""
        # Implementation would analyze target to determine asset types
        return ["web", "mobile", "api"]

    async def map_attack_surface(self, target: str) -> Dict[str, Any]:
        """Map the attack surface of the target"""
        return {"endpoints": [], "services": [], "technologies": []}

    async def detect_technologies(self, target: str) -> Dict[str, Any]:
        """Detect technologies used by the target"""
        return {"web_server": "nginx", "framework": "react", "language": "python"}

    async def analyze_business_context(self, target: str) -> Dict[str, Any]:
        """Analyze business context for prioritization"""
        return {"industry": "unknown", "data_sensitivity": "medium", "compliance": []}

    async def assess_risk_profile(self, target: str) -> Dict[str, Any]:
        """Assess risk profile of the target"""
        return {"risk_level": "medium", "exposure": "internet", "criticality": "medium"}


class StrategyEngine:
    """AI-driven strategy engine for creating testing strategies"""

    async def create_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive testing strategy based on target analysis"""
        strategy = {
            "approach": "comprehensive",
            "agent_sequence": ["recon_agent", "osint_agent", "sast_agent", "dast_agent"],
            "duration": "4-6 hours",
            "resources": {"memory": "4GB", "cpu": "60%"},
            "priorities": ["high_severity_vulns", "business_logic", "authentication"]
        }

        # Adapt strategy based on analysis
        if analysis["risk_profile"]["risk_level"] == "high":
            strategy["approach"] = "intensive"
            strategy["agent_sequence"].append("binary_analysis_agent")

        if "api" in analysis["asset_types"]:
            strategy["agent_sequence"].insert(2, "api_testing_agent")

        return strategy


class PriorityManager:
    """Manages task prioritization and resource allocation"""

    def calculate_priority(self, task: AgentTask, context: Dict[str, Any]) -> int:
        """Calculate dynamic priority for tasks"""
        base_priority = task.priority

        # Boost priority based on findings
        if context.get("critical_vulns_found", 0) > 0:
            base_priority += 2

        return min(base_priority, 10)  # Cap at 10


class ResourceAllocator:
    """Manages resource allocation for agents"""

    def allocate_resources(self, active_tasks: List[AgentTask]) -> Dict[str, Any]:
        """Allocate resources based on active tasks"""
        return {
            "memory_per_task": "512MB",
            "cpu_per_task": "20%",
            "max_concurrent": 5
        }


class LearningEngine:
    """Continuous learning from execution results"""

    async def learn_from_execution(self, execution_results: Dict[str, Any]) -> None:
        """Learn from execution results to improve future decisions"""
        # Implementation would update ML models based on results
        logging.info(f"Learning from execution {execution_results['session_id']}")

        # Update strategy preferences
        # Update agent effectiveness metrics
        # Update vulnerability prediction models
        pass


if __name__ == "__main__":
    # Example usage
    async def main():
        orchestrator = OrchestratorAgent()

        # Analyze target
        analysis = await orchestrator.analyze_target("example.com", ["example.com", "*.example.com"])

        # Create execution plan
        plan = await orchestrator.create_execution_plan(analysis)

        # Execute orchestration
        results = await orchestrator.execute_orchestration(plan)

        print(f"Orchestration completed: {results['completed_tasks']} tasks")

    asyncio.run(main())