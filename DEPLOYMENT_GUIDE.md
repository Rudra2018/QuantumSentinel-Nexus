# QuantumSentinel-Nexus v4.0 - Deployment Guide

## 🚀 Quick Start Deployment

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd QuantumSentinel-Nexus

# Build production image
docker build -t quantumsentinel-nexus:v4.0 .

# Or build testing image (faster)
docker build -f Dockerfile.simple -t quantumsentinel-nexus:simple .

# Run assessment
docker run --rm -v $(pwd)/targets:/app/targets quantumsentinel-nexus:v4.0 \
  python3 autonomous_quantum_sentinel.py --target example.com
```

### Option 2: Native Installation
```bash
# Install Python dependencies
pip install -r requirements-docker.txt  # Minimal
# OR
pip install -r requirements.txt         # Full with all ML libraries

# Run system test
python3 test_system.py

# Execute assessment
python3 autonomous_quantum_sentinel.py --target example.com
```

## 🎯 Assessment Execution

### 1. Prepare Target Configuration
```bash
# Add authorized target to scope file
echo "example.com" >> targets/authorized_scope.txt
echo "*.example.com" >> targets/authorized_scope.txt
```

### 2. Run Comprehensive Assessment
```bash
# AI-powered autonomous assessment (v4.0)
python3 autonomous_quantum_sentinel.py --target example.com --comprehensive

# Traditional orchestrated assessment (v3.0)
python3 quantumsentinel_orchestrator.py --target example.com

# Mobile security assessment
python3 mobile_security/unified_mobile_security_orchestrator.py --apk app.apk
```

### 3. Monitor Assessment Progress
```bash
# Follow assessment logs
tail -f assessments/*/logs/assessment.log

# Check real-time status
docker logs -f <container-id>
```

## 🐳 Docker Deployment Options

### Single Container
```bash
# Run interactive assessment
docker run -it --rm \
  -v $(pwd)/targets:/app/targets \
  -v $(pwd)/assessments:/app/assessments \
  quantumsentinel-nexus:v4.0 bash

# Run automated assessment
docker run --rm \
  -v $(pwd)/targets:/app/targets \
  -v $(pwd)/assessments:/app/assessments \
  quantumsentinel-nexus:v4.0 \
  python3 autonomous_quantum_sentinel.py --target example.com
```

### Docker Compose (Multi-Service)
```bash
# Deploy full infrastructure
docker-compose up -d

# Scale workers
docker-compose up --scale quantum-worker=3

# Monitor services
docker-compose logs -f
```

## ⚙️ Configuration

### Environment Variables
```bash
export QUANTUM_TARGET="example.com"
export QUANTUM_SCOPE_FILE="/app/targets/authorized_scope.txt"
export QUANTUM_ASSESSMENT_TYPE="comprehensive"
export QUANTUM_AI_ENABLED="true"
export QUANTUM_LEARNING_ENABLED="true"
```

### Configuration Files
```yaml
# config/assessment.yaml
assessment:
  target: "example.com"
  scope_file: "targets/authorized_scope.txt"
  type: "comprehensive"
  ai_enabled: true
  learning_enabled: true

modules:
  sast: true
  dast: true
  binary_analysis: true
  mobile_security: true
  osint: true

output:
  format: "pdf"
  include_evidence: true
  include_screenshots: true
```

## 🎯 Assessment Types

### Comprehensive Assessment (Recommended)
```bash
python3 autonomous_quantum_sentinel.py \
  --target example.com \
  --comprehensive \
  --ai-enabled \
  --learning-enabled
```

### Focused Assessments
```bash
# SAST only
python3 autonomous_quantum_sentinel.py --target example.com --sast-only

# DAST only
python3 autonomous_quantum_sentinel.py --target example.com --dast-only

# Mobile only
python3 mobile_security/unified_mobile_security_orchestrator.py --apk app.apk

# OSINT only
python3 -m modules.osint_module --target example.com
```

## 📊 Output Management

### Report Generation
```bash
# Generate PDF report
python3 autonomous_quantum_sentinel.py --target example.com --report-pdf

# Generate HTML report
python3 autonomous_quantum_sentinel.py --target example.com --report-html

# Generate JSON export
python3 autonomous_quantum_sentinel.py --target example.com --export-json
```

### Assessment Results Structure
```
assessments/
├── <target>_<timestamp>/
│   ├── evidence/
│   │   ├── recon/
│   │   ├── osint/
│   │   ├── vulnerabilities/
│   │   └── consolidated/
│   ├── reports/
│   │   ├── executive_summary.pdf
│   │   ├── technical_report.pdf
│   │   └── raw_findings.json
│   ├── screenshots/
│   └── logs/
```

## 🛡️ Security & Compliance

### Pre-Assessment Checklist
- [ ] Target is in authorized scope file
- [ ] Legal authorization obtained
- [ ] Rate limiting configured
- [ ] Network isolation verified
- [ ] Logging enabled
- [ ] Backup procedures in place

### During Assessment
- Monitor resource usage
- Verify network traffic
- Check rate limiting effectiveness
- Review real-time logs
- Ensure ethical compliance

### Post-Assessment
- Verify report accuracy
- Remove sensitive data
- Archive assessment data
- Update learning models
- Document lessons learned

## 🔧 Troubleshooting

### Common Issues

**Import Errors**
```bash
# Install missing dependencies
pip install -r requirements.txt

# Use Docker if native issues persist
docker run --rm quantumsentinel-nexus:simple python3 test_system.py
```

**Permission Errors**
```bash
# Fix permissions
sudo chown -R $USER:$USER assessments/
chmod +x scripts/*.sh
```

**Network Issues**
```bash
# Test connectivity
docker run --rm quantumsentinel-nexus:simple python3 -c "import requests; print(requests.get('https://httpbin.org/ip').text)"
```

### System Health Check
```bash
# Run comprehensive system test
python3 test_system.py

# Check Docker health
docker run --rm quantumsentinel-nexus:simple python3 -c "print('System operational!')"

# Verify AI components
python3 -c "from ai_core.quantum_sentinel_ml import QuantumSentinelML; print('AI system ready!')"
```

## 📈 Performance Optimization

### Resource Requirements
- **Minimum**: 4GB RAM, 2 CPU cores, 10GB storage
- **Recommended**: 8GB RAM, 4 CPU cores, 50GB storage
- **Optimal**: 16GB RAM, 8 CPU cores, 100GB storage

### Scaling Options
```bash
# Horizontal scaling with Docker Swarm
docker swarm init
docker service create --replicas 3 quantumsentinel-nexus:v4.0

# Kubernetes deployment
kubectl apply -f k8s/quantum-sentinel-deployment.yaml
```

## 📞 Support & Monitoring

### Health Monitoring
```bash
# System status
curl http://localhost:8080/health

# Metrics endpoint
curl http://localhost:8080/metrics

# Assessment status
curl http://localhost:8080/assessments/<id>/status
```

### Logs & Debugging
```bash
# Application logs
docker logs quantumsentinel-nexus

# Assessment logs
tail -f assessments/*/logs/assessment.log

# System debug
python3 test_system.py --debug
```

---

**Ready to deploy QuantumSentinel-Nexus v4.0 for autonomous AI security testing!**