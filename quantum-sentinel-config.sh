#!/bin/bash
# QuantumSentinel-Nexus Configuration
export GOOGLE_CLOUD_PROJECT="quantumsentinel-nexus-9957"
export GOOGLE_CLOUD_REGION="us-central1"
export GOOGLE_CLOUD_ZONE="us-central1-a"
export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/quantum-sentinel-sa-key.json"

# Bucket names
export QUANTUM_REPORTS_BUCKET="quantumsentinel-nexus-9957-quantum-reports"
export QUANTUM_RESEARCH_DATA_BUCKET="quantumsentinel-nexus-9957-quantum-research-data"
export QUANTUM_ML_MODELS_BUCKET="quantumsentinel-nexus-9957-quantum-ml-models"
export QUANTUM_EVIDENCE_BUCKET="quantumsentinel-nexus-9957-quantum-evidence"
export QUANTUM_CONFIGS_BUCKET="quantumsentinel-nexus-9957-quantum-configs"
export QUANTUM_LOGS_BUCKET="quantumsentinel-nexus-9957-quantum-logs"

# Service account
export QUANTUM_SERVICE_ACCOUNT="quantum-sentinel-sa@quantumsentinel-nexus-9957.iam.gserviceaccount.com"

echo "QuantumSentinel-Nexus configuration loaded for project: quantumsentinel-nexus-9957"
