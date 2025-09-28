#!/bin/bash
# QuantumSentinel-Nexus AWS Configuration
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="077732578302"
export CLOUDFORMATION_STACK_NAME="quantum-auto-t09281201"

# S3 Bucket names
export QUANTUM_REPORTS_BUCKET="quantumsentinel-nexus-quantum-reports-077732578302"
export QUANTUM_RESEARCH_DATA_BUCKET="quantumsentinel-nexus-quantum-research-data-077732578302"
export QUANTUM_ML_MODELS_BUCKET="quantumsentinel-nexus-quantum-ml-models-077732578302"
export QUANTUM_EVIDENCE_BUCKET="quantumsentinel-nexus-quantum-evidence-077732578302"
export QUANTUM_CONFIGS_BUCKET="quantumsentinel-nexus-quantum-configs-077732578302"
export QUANTUM_LOGS_BUCKET="quantumsentinel-nexus-quantum-logs-077732578302"

# IAM Role
export QUANTUM_ROLE_ARN="arn:aws:iam::077732578302:role/quantumsentinel-nexus-execution-role"

# ECR Repository
export QUANTUM_ECR_REPOSITORY="077732578302.dkr.ecr.us-east-1.amazonaws.com/quantumsentinel-nexus"

echo "QuantumSentinel-Nexus AWS configuration loaded for account: 077732578302"
