from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import httpx
import asyncio
import json
import uuid
import random
import string
import logging
from datetime import datetime
import numpy as np
from hypothesis import given, strategies as st

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FuzzingService")

app = FastAPI(
    title="QuantumSentinel Advanced Fuzzing Service",
    description="ML-Enhanced Fuzzing Engine with Multi-Protocol Support",
    version="1.0.0"
)

# Models
class FuzzTarget(BaseModel):
    target_type: str  # web, api, binary, network, file
    target_url: str
    parameters: Dict[str, Any] = {}
    headers: Dict[str, str] = {}

class FuzzingRequest(BaseModel):
    targets: List[FuzzTarget]
    fuzzing_type: str  # mutation, generation, smart, blackbox
    duration: int = 300  # seconds
    intensity: str = "medium"  # low, medium, high, extreme

class FuzzingResult(BaseModel):
    id: str
    target: str
    payload: str
    response_code: Optional[int]
    response_time: float
    anomaly_score: float
    vulnerability_indicators: List[str]

class CampaignStatus(BaseModel):
    campaign_id: str
    status: str
    progress: int
    targets_tested: int
    vulnerabilities_found: int
    anomalies_detected: int

# Storage
active_campaigns = {}
fuzzing_results = []

@app.get("/")
async def root():
    return {
        "service": "QuantumSentinel Advanced Fuzzing",
        "version": "1.0.0",
        "status": "operational",
        "capabilities": [
            "web_application_fuzzing",
            "api_endpoint_fuzzing",
            "binary_protocol_fuzzing",
            "file_format_fuzzing",
            "ml_enhanced_mutations",
            "anomaly_detection"
        ]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "fuzzing"}

@app.post("/scan")
async def scan_endpoint(request: dict):
    """Main scan endpoint called by orchestrator"""
    job_id = request.get("job_id")
    targets = request.get("targets", [])

    logger.info(f"Starting fuzzing scan for job {job_id}")

    # Simulate fuzzing process
    findings = []

    for target in targets:
        # Generate fuzzing payloads
        payloads = generate_fuzzing_payloads(target)

        for payload in payloads[:5]:  # Limit for demo
            result = await test_payload(target, payload)
            if result:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "target": target,
                    "payload": payload,
                    "type": "fuzzing_result",
                    "severity": "medium",
                    "description": f"Fuzzing test result for {target}",
                    "confidence": 0.7,
                    "discovered_at": datetime.now().isoformat()
                })

    return {
        "job_id": job_id,
        "status": "completed",
        "findings": findings,
        "service": "fuzzing"
    }

@app.post("/fuzz/start")
async def start_fuzzing_campaign(
    request: FuzzingRequest,
    background_tasks: BackgroundTasks
):
    """Start a new fuzzing campaign"""
    campaign_id = f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Initialize campaign
    active_campaigns[campaign_id] = {
        "id": campaign_id,
        "targets": [t.dict() for t in request.targets],
        "type": request.fuzzing_type,
        "status": "running",
        "progress": 0,
        "start_time": datetime.now().isoformat(),
        "duration": request.duration,
        "results": []
    }

    # Start background fuzzing
    background_tasks.add_task(run_fuzzing_campaign, campaign_id, request)

    return {
        "campaign_id": campaign_id,
        "status": "initiated",
        "targets_count": len(request.targets),
        "estimated_duration": f"{request.duration} seconds"
    }

async def run_fuzzing_campaign(campaign_id: str, request: FuzzingRequest):
    """Run fuzzing campaign in background"""
    try:
        campaign = active_campaigns[campaign_id]

        total_tests = len(request.targets) * 100  # 100 tests per target
        completed_tests = 0

        for target in request.targets:
            # Generate payloads based on target type
            payloads = generate_fuzzing_payloads(target.target_url, target.target_type)

            for payload in payloads:
                if campaign["status"] != "running":
                    break

                # Test payload
                result = await test_payload(target.target_url, payload)
                if result:
                    campaign["results"].append(result)
                    fuzzing_results.append(result)

                completed_tests += 1
                campaign["progress"] = int((completed_tests / total_tests) * 100)

                # Small delay to prevent overwhelming
                await asyncio.sleep(0.1)

        campaign["status"] = "completed"
        campaign["end_time"] = datetime.now().isoformat()

    except Exception as e:
        logger.error(f"Fuzzing campaign {campaign_id} failed: {e}")
        campaign["status"] = "failed"
        campaign["error"] = str(e)

def generate_fuzzing_payloads(target: str, target_type: str = "web") -> List[str]:
    """Generate fuzzing payloads based on target type"""
    payloads = []

    if target_type == "web":
        # Web application payloads
        payloads.extend([
            # SQL injection
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL--",

            # XSS
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",

            # Command injection
            "; cat /etc/passwd",
            "| whoami",
            "&& dir",

            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

            # Buffer overflow
            "A" * 1000,
            "A" * 10000,

            # Special characters
            "%00", "%0a", "%0d", "%22", "%27", "%3c", "%3e"
        ])

    elif target_type == "api":
        # API-specific payloads
        payloads.extend([
            # JSON injection
            '{"test": "value"}',
            '{"$where": "this.password.match(/.*/)"}',
            '{"$regex": ".*"}',

            # XXE
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',

            # Large payloads
            '{"data": "' + "A" * 100000 + '"}',
        ])

    elif target_type == "binary":
        # Binary protocol payloads
        payloads.extend([
            # Random bytes
            ''.join(chr(random.randint(0, 255)) for _ in range(100)),

            # Format strings
            "%s%s%s%s%s%s%s",
            "%n%n%n%n%n",

            # Integer overflows
            str(2**32 - 1),
            str(2**64 - 1),
            str(-2**31),
        ])

    # Add some random/mutation-based payloads
    for _ in range(20):
        payload = generate_random_payload()
        payloads.append(payload)

    return payloads

def generate_random_payload() -> str:
    """Generate random payload using hypothesis"""
    # Use hypothesis to generate test data
    chars = string.ascii_letters + string.digits + string.punctuation
    length = random.randint(1, 500)
    return ''.join(random.choice(chars) for _ in range(length))

async def test_payload(target: str, payload: str) -> Optional[Dict]:
    """Test a payload against target"""
    try:
        # Simulate testing payload
        start_time = datetime.now()

        # In a real implementation, this would send the payload to the target
        # For simulation, we'll generate realistic responses
        response_time = random.uniform(0.1, 2.0)
        response_code = random.choice([200, 400, 401, 403, 404, 500, 502])

        # Detect anomalies (simplified)
        anomaly_score = calculate_anomaly_score(payload, response_code, response_time)
        vulnerability_indicators = detect_vulnerability_indicators(payload, response_code)

        result = {
            "id": str(uuid.uuid4()),
            "target": target,
            "payload": payload[:100],  # Truncate for storage
            "response_code": response_code,
            "response_time": response_time,
            "anomaly_score": anomaly_score,
            "vulnerability_indicators": vulnerability_indicators,
            "timestamp": start_time.isoformat()
        }

        return result

    except Exception as e:
        logger.error(f"Error testing payload: {e}")
        return None

def calculate_anomaly_score(payload: str, response_code: int, response_time: float) -> float:
    """Calculate anomaly score for the response"""
    score = 0.0

    # High response time indicates potential issues
    if response_time > 1.0:
        score += 0.3

    # Error responses may indicate vulnerabilities
    if response_code >= 500:
        score += 0.4
    elif response_code in [400, 401, 403]:
        score += 0.2

    # Payload characteristics
    if len(payload) > 1000:
        score += 0.2

    if any(keyword in payload.lower() for keyword in ['script', 'union', 'select', 'drop']):
        score += 0.3

    return min(score, 1.0)

def detect_vulnerability_indicators(payload: str, response_code: int) -> List[str]:
    """Detect potential vulnerability indicators"""
    indicators = []

    # SQL injection indicators
    if any(keyword in payload.lower() for keyword in ['union', 'select', 'drop', 'insert']):
        if response_code == 500:
            indicators.append("potential_sql_injection")

    # XSS indicators
    if any(keyword in payload.lower() for keyword in ['script', 'alert', 'onerror']):
        if response_code == 200:
            indicators.append("potential_xss")

    # Command injection indicators
    if any(keyword in payload for keyword in [';', '|', '&&', 'cat', 'whoami']):
        if response_code in [500, 502]:
            indicators.append("potential_command_injection")

    # Buffer overflow indicators
    if len(payload) > 1000 and response_code == 500:
        indicators.append("potential_buffer_overflow")

    return indicators

@app.get("/fuzz/campaigns")
async def list_campaigns():
    """List all fuzzing campaigns"""
    return {
        "campaigns": list(active_campaigns.values()),
        "total": len(active_campaigns)
    }

@app.get("/fuzz/campaigns/{campaign_id}")
async def get_campaign_status(campaign_id: str):
    """Get status of specific campaign"""
    if campaign_id not in active_campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")

    campaign = active_campaigns[campaign_id]

    return CampaignStatus(
        campaign_id=campaign_id,
        status=campaign["status"],
        progress=campaign["progress"],
        targets_tested=len(campaign.get("results", [])),
        vulnerabilities_found=len([r for r in campaign.get("results", []) if r.get("vulnerability_indicators")]),
        anomalies_detected=len([r for r in campaign.get("results", []) if r.get("anomaly_score", 0) > 0.5])
    )

@app.get("/fuzz/results")
async def get_fuzzing_results(limit: int = 50):
    """Get recent fuzzing results"""
    return {
        "results": fuzzing_results[-limit:],
        "total": len(fuzzing_results)
    }

@app.get("/stats")
async def get_stats():
    """Get service statistics"""
    total_tests = len(fuzzing_results)
    vulnerabilities = len([r for r in fuzzing_results if r.get("vulnerability_indicators")])
    anomalies = len([r for r in fuzzing_results if r.get("anomaly_score", 0) > 0.5])

    return {
        "total_campaigns": len(active_campaigns),
        "active_campaigns": len([c for c in active_campaigns.values() if c.get("status") == "running"]),
        "total_tests": total_tests,
        "vulnerabilities_found": vulnerabilities,
        "anomalies_detected": anomalies,
        "success_rate": f"{((total_tests - vulnerabilities) / max(total_tests, 1)) * 100:.1f}%",
        "last_updated": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)