import os
from fastapi import FastAPI
from datetime import datetime

app = FastAPI(title="QuantumSentinel-Nexus Test Service")

@app.get("/")
def root():
    return {
        "message": "QuantumSentinel-Nexus Test Service",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
def health():
    return {"status": "healthy", "service": "test"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
