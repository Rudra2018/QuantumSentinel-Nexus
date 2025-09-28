#!/usr/bin/env python3
"""
🔬 BINARY ANALYSIS SERVICE - QuantumSentinel-Nexus v6.0
========================================================
Advanced binary analysis and reverse engineering service
for comprehensive vulnerability detection and exploit development.
"""

import asyncio
import json
import logging
import os
import tempfile
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, File, UploadFile, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx
import aiofiles

# Import the comprehensive binary analysis engine
import sys
sys.path.append('/app')
from ai_agents.binary_analysis_agent import BinaryAnalysisAgent, VulnerabilityReport

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QuantumSentinel.BinaryAnalysis")

app = FastAPI(
    title="QuantumSentinel Binary Analysis Service",
    description="Advanced binary analysis and reverse engineering service",
    version="6.0.0"
)

# Global agent instance
binary_agent = None
service_ips = {}

class BinaryAnalysisRequest(BaseModel):
    target: str = Field(..., description="Target binary path or URL")
    analysis_depth: str = Field(default="comprehensive", description="Analysis depth: basic, moderate, comprehensive")
    exploit_development: bool = Field(default=True, description="Generate exploit analysis")
    symbolic_execution: bool = Field(default=True, description="Enable symbolic execution")
    priority: str = Field(default="medium", description="Analysis priority")

class BinarySubmissionResponse(BaseModel):
    analysis_id: str
    status: str
    message: str
    estimated_completion: str

class BinaryAnalysisResult(BaseModel):
    analysis_id: str
    status: str
    target: str
    metadata: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    exploit_analysis: Dict[str, Any]
    recommendations: List[str]
    confidence: float
    analysis_time: float

# Store analysis results
analysis_results = {}
active_analyses = {}

@app.on_startup
async def startup_event():
    """Initialize the binary analysis service"""
    global binary_agent, service_ips

    logger.info("🔬 Initializing Binary Analysis Service v6.0")

    # Initialize binary analysis agent
    binary_agent = BinaryAnalysisAgent()

    # Load service IPs for integration
    try:
        with open('/app/service_ips.txt', 'r') as f:
            for line in f:
                if ':' in line and not line.strip().startswith('#'):
                    service, ip = line.strip().split(': ')
                    service_ips[service] = ip
        logger.info(f"📡 Loaded {len(service_ips)} service IPs for integration")
    except Exception as e:
        logger.warning(f"Could not load service IPs: {e}")
        service_ips = {}

    logger.info("✅ Binary Analysis Service initialized successfully")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "QuantumSentinel Binary Analysis Service",
        "version": "6.0.0",
        "status": "operational",
        "capabilities": [
            "Static binary analysis",
            "Dynamic analysis and emulation",
            "Symbolic execution",
            "Vulnerability detection",
            "Exploit primitive discovery",
            "ML-powered insights",
            "Multi-architecture support"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "binary-analysis-service",
        "version": "6.0.0",
        "uptime": datetime.now().isoformat(),
        "active_analyses": len(active_analyses),
        "completed_analyses": len(analysis_results)
    }

@app.post("/analyze", response_model=BinarySubmissionResponse)
async def submit_binary_analysis(
    background_tasks: BackgroundTasks,
    request: BinaryAnalysisRequest
):
    """Submit a binary for comprehensive analysis"""
    analysis_id = f"BIN-{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(request.target) % 10000:04d}"

    logger.info(f"🔬 Received binary analysis request: {analysis_id}")
    logger.info(f"📁 Target: {request.target}")
    logger.info(f"🎯 Analysis depth: {request.analysis_depth}")

    # Add to active analyses
    active_analyses[analysis_id] = {
        "id": analysis_id,
        "target": request.target,
        "status": "queued",
        "start_time": datetime.now().isoformat(),
        "priority": request.priority
    }

    # Schedule background analysis
    background_tasks.add_task(
        perform_binary_analysis,
        analysis_id,
        request
    )

    return BinarySubmissionResponse(
        analysis_id=analysis_id,
        status="queued",
        message=f"Binary analysis submitted for {request.target}",
        estimated_completion=f"{60 if request.analysis_depth == 'comprehensive' else 30} minutes"
    )

@app.post("/analyze/upload", response_model=BinarySubmissionResponse)
async def upload_and_analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_depth: str = Form(default="comprehensive"),
    exploit_development: bool = Form(default=True),
    symbolic_execution: bool = Form(default=True),
    priority: str = Form(default="medium")
):
    """Upload a binary file and analyze it"""

    # Create temporary file
    temp_dir = "/tmp/binary_uploads"
    os.makedirs(temp_dir, exist_ok=True)

    # Save uploaded file
    file_hash = hashlib.sha256(await file.read()).hexdigest()
    await file.seek(0)

    temp_file_path = f"{temp_dir}/{file_hash}_{file.filename}"

    async with aiofiles.open(temp_file_path, 'wb') as f:
        content = await file.read()
        await f.write(content)

    # Create analysis request
    request = BinaryAnalysisRequest(
        target=temp_file_path,
        analysis_depth=analysis_depth,
        exploit_development=exploit_development,
        symbolic_execution=symbolic_execution,
        priority=priority
    )

    analysis_id = f"BIN-UPLOAD-{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_hash[:8]}"

    logger.info(f"📤 Uploaded binary for analysis: {analysis_id}")
    logger.info(f"📁 File: {file.filename} ({len(content)} bytes)")

    # Add to active analyses
    active_analyses[analysis_id] = {
        "id": analysis_id,
        "target": f"uploaded:{file.filename}",
        "file_path": temp_file_path,
        "status": "queued",
        "start_time": datetime.now().isoformat(),
        "priority": priority
    }

    # Schedule background analysis
    background_tasks.add_task(
        perform_binary_analysis,
        analysis_id,
        request
    )

    return BinarySubmissionResponse(
        analysis_id=analysis_id,
        status="queued",
        message=f"Binary file {file.filename} uploaded and queued for analysis",
        estimated_completion=f"{60 if analysis_depth == 'comprehensive' else 30} minutes"
    )

@app.get("/analysis/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """Get analysis results"""

    # Check if analysis is complete
    if analysis_id in analysis_results:
        return analysis_results[analysis_id]

    # Check if analysis is still active
    if analysis_id in active_analyses:
        return {
            "analysis_id": analysis_id,
            "status": active_analyses[analysis_id]["status"],
            "target": active_analyses[analysis_id]["target"],
            "start_time": active_analyses[analysis_id]["start_time"],
            "message": "Analysis in progress..."
        }

    raise HTTPException(status_code=404, detail="Analysis not found")

@app.get("/analysis")
async def list_analyses(
    status: Optional[str] = None,
    limit: int = 20
):
    """List all analyses"""

    all_analyses = []

    # Add completed analyses
    for analysis_id, result in list(analysis_results.items())[-limit:]:
        if not status or result.get("status") == status:
            all_analyses.append({
                "analysis_id": analysis_id,
                "status": result.get("status", "completed"),
                "target": result.get("target"),
                "vulnerabilities_found": len(result.get("vulnerabilities", [])),
                "confidence": result.get("confidence", 0.0),
                "completion_time": result.get("end_time")
            })

    # Add active analyses
    for analysis_id, active in active_analyses.items():
        if not status or active["status"] == status:
            all_analyses.append({
                "analysis_id": analysis_id,
                "status": active["status"],
                "target": active["target"],
                "start_time": active["start_time"]
            })

    return {
        "analyses": all_analyses,
        "total": len(all_analyses),
        "active_count": len(active_analyses),
        "completed_count": len(analysis_results)
    }

@app.get("/statistics")
async def get_statistics():
    """Get binary analysis statistics"""

    total_analyses = len(analysis_results) + len(active_analyses)
    total_vulnerabilities = sum(len(r.get("vulnerabilities", [])) for r in analysis_results.values())

    # Calculate vulnerability distribution
    vuln_types = {}
    for result in analysis_results.values():
        for vuln in result.get("vulnerabilities", []):
            vuln_type = vuln.get("vuln_class", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

    return {
        "total_analyses": total_analyses,
        "completed_analyses": len(analysis_results),
        "active_analyses": len(active_analyses),
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerability_distribution": vuln_types,
        "service_uptime": datetime.now().isoformat()
    }

@app.post("/integrate/scan")
async def trigger_integrated_scan(request: Dict[str, Any]):
    """Trigger binary analysis as part of integrated scanning"""

    target = request.get("target")
    scan_id = request.get("scan_id", f"INTEGRATED-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    priority = request.get("priority", "high")

    logger.info(f"🔗 Received integrated scan request for: {target}")

    # Create analysis request with high priority for integrated scans
    analysis_request = BinaryAnalysisRequest(
        target=target,
        analysis_depth="comprehensive",
        exploit_development=True,
        symbolic_execution=True,
        priority=priority
    )

    analysis_id = f"INT-{scan_id}-{hash(target) % 10000:04d}"

    # Add to active analyses
    active_analyses[analysis_id] = {
        "id": analysis_id,
        "target": target,
        "status": "analyzing",
        "start_time": datetime.now().isoformat(),
        "priority": priority,
        "integrated_scan": True,
        "scan_id": scan_id
    }

    # Perform analysis immediately for integrated scans
    asyncio.create_task(perform_binary_analysis(analysis_id, analysis_request))

    return {
        "analysis_id": analysis_id,
        "status": "started",
        "message": f"Integrated binary analysis started for {target}",
        "scan_id": scan_id
    }

async def perform_binary_analysis(analysis_id: str, request: BinaryAnalysisRequest):
    """Perform the actual binary analysis"""

    logger.info(f"🔬 Starting binary analysis: {analysis_id}")
    start_time = datetime.now()

    try:
        # Update status
        if analysis_id in active_analyses:
            active_analyses[analysis_id]["status"] = "analyzing"

        # Create mock task for the agent
        class MockTask:
            def __init__(self, target: str, params: Dict[str, Any]):
                self.task_id = analysis_id
                self.target = target
                self.parameters = params

        task = MockTask(
            target=request.target,
            params={
                "analysis_depth": request.analysis_depth,
                "exploit_development": request.exploit_development,
                "symbolic_execution": request.symbolic_execution
            }
        )

        # Perform analysis using the binary agent
        logger.info(f"🧠 Executing comprehensive binary analysis for: {request.target}")

        results = await binary_agent.execute(task)

        # Process results
        analysis_time = (datetime.now() - start_time).total_seconds()

        # Create comprehensive result
        final_result = {
            "analysis_id": analysis_id,
            "status": "completed",
            "target": request.target,
            "metadata": results.get("analysis_results", {}).get("metadata", {}),
            "static_analysis": results.get("analysis_results", {}).get("static_analysis", {}),
            "dynamic_analysis": results.get("analysis_results", {}).get("dynamic_analysis", {}),
            "function_analysis": results.get("analysis_results", {}).get("function_analysis", {}),
            "vulnerabilities": results.get("vulnerabilities", []),
            "exploit_analysis": results.get("exploit_analysis", {}),
            "ai_insights": results.get("analysis_results", {}).get("ai_insights", {}),
            "recommendations": await generate_recommendations(results),
            "confidence": results.get("confidence", 0.0),
            "analysis_time": analysis_time,
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "service_version": "6.0.0"
        }

        # Store results
        analysis_results[analysis_id] = final_result

        # Remove from active analyses
        if analysis_id in active_analyses:
            # Check if this was an integrated scan
            integrated_scan = active_analyses[analysis_id].get("integrated_scan", False)
            scan_id = active_analyses[analysis_id].get("scan_id")

            del active_analyses[analysis_id]

            # If integrated scan, notify orchestrator
            if integrated_scan:
                await notify_scan_completion(scan_id, analysis_id, final_result)

        logger.info(f"✅ Binary analysis completed: {analysis_id}")
        logger.info(f"🔍 Found {len(final_result['vulnerabilities'])} vulnerabilities")
        logger.info(f"⏱️ Analysis time: {analysis_time:.2f} seconds")

    except Exception as e:
        logger.error(f"❌ Binary analysis failed: {analysis_id} - {e}")

        # Store error result
        error_result = {
            "analysis_id": analysis_id,
            "status": "failed",
            "target": request.target,
            "error": str(e),
            "analysis_time": (datetime.now() - start_time).total_seconds(),
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat()
        }

        analysis_results[analysis_id] = error_result

        # Remove from active analyses
        if analysis_id in active_analyses:
            del active_analyses[analysis_id]

async def generate_recommendations(analysis_results: Dict[str, Any]) -> List[str]:
    """Generate actionable recommendations based on analysis results"""

    recommendations = []

    vulnerabilities = analysis_results.get("vulnerabilities", [])
    ai_insights = analysis_results.get("analysis_results", {}).get("ai_insights", {})

    # Vulnerability-based recommendations
    if vulnerabilities:
        high_severity = [v for v in vulnerabilities if v.get("severity") in ["critical", "high"]]
        if high_severity:
            recommendations.append(f"🚨 Immediate action required: {len(high_severity)} high/critical vulnerabilities found")

            # Specific vulnerability recommendations
            vuln_types = [v.get("vuln_class") for v in high_severity]
            if "buffer_overflow" in vuln_types:
                recommendations.append("🛡️ Enable stack canaries and use safe string functions")
            if "hardcoded_credentials" in vuln_types:
                recommendations.append("🔐 Remove hardcoded credentials and implement secure storage")

    # AI insights based recommendations
    risk_assessment = ai_insights.get("risk_assessment", {})
    if risk_assessment.get("overall_risk_score", 0) > 0.7:
        recommendations.append("⚠️ High overall risk detected - conduct thorough security review")

    # Security features recommendations
    metadata = analysis_results.get("analysis_results", {}).get("metadata", {})
    security_features = metadata.get("security_features", {})

    if not security_features.get("stack_canary"):
        recommendations.append("🛡️ Enable stack protection during compilation")
    if not security_features.get("pic_pie"):
        recommendations.append("🔀 Compile with Position Independent Executable (PIE)")

    # Default recommendation if no issues found
    if not recommendations:
        recommendations.append("✅ Binary shows good security posture - maintain current practices")

    return recommendations

async def notify_scan_completion(scan_id: str, analysis_id: str, results: Dict[str, Any]):
    """Notify orchestrator about scan completion"""

    try:
        # Notify orchestrator service if available
        orchestrator_ip = service_ips.get("quantumsentinel-orchestration")
        if orchestrator_ip:
            notification_data = {
                "scan_id": scan_id,
                "analysis_id": analysis_id,
                "service": "binary-analysis",
                "status": "completed",
                "vulnerabilities_found": len(results.get("vulnerabilities", [])),
                "confidence": results.get("confidence", 0.0),
                "completion_time": results.get("end_time")
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                await client.post(
                    f"http://{orchestrator_ip}:8001/scan/notify",
                    json=notification_data
                )

            logger.info(f"📡 Notified orchestrator about completed analysis: {analysis_id}")

    except Exception as e:
        logger.warning(f"Failed to notify orchestrator: {e}")

# Service management endpoints
@app.post("/admin/clear_cache")
async def clear_analysis_cache():
    """Clear analysis cache (admin only)"""
    global analysis_results, active_analyses

    cleared_completed = len(analysis_results)
    cleared_active = len(active_analyses)

    analysis_results.clear()
    active_analyses.clear()

    return {
        "message": "Analysis cache cleared",
        "cleared_completed": cleared_completed,
        "cleared_active": cleared_active
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)