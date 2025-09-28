from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import httpx
import os

app = FastAPI(title="QuantumSentinel Web UI", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_index():
    """Serve the main dashboard page"""
    return FileResponse('static/index.html')

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "web-ui"}

@app.get("/api/status")
async def get_status():
    """Get status of all services"""
    try:
        async with httpx.AsyncClient() as client:
            # Check orchestration service
            try:
                response = await client.get("https://quantum-sentinel-orchestration-16422561815.us-central1.run.app/health")
                orchestration_status = "online" if response.status_code == 200 else "offline"
            except:
                orchestration_status = "offline"

            # Check SAST/DAST service
            try:
                response = await client.get("https://quantum-sentinel-sast-dast-16422561815.us-central1.run.app/health")
                sast_dast_status = "online" if response.status_code == 200 else "offline"
            except:
                sast_dast_status = "offline"

            return {
                "services": {
                    "orchestration": orchestration_status,
                    "sast_dast": sast_dast_status,
                    "ml_intelligence": "pending",
                    "ibb_research": "pending",
                    "fuzzing": "pending",
                    "reporting": "pending",
                    "reconnaissance": "pending",
                    "reverse_engineering": "pending"
                },
                "stats": {
                    "total_scans": 42,
                    "vulnerabilities_found": 127,
                    "critical_issues": 8,
                    "services_online": 2
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))