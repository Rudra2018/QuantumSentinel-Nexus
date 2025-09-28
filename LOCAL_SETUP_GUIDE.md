# 🛡️ QuantumSentinel-Nexus Local Setup Guide

**Complete Local Development Environment Setup**

## 📋 Prerequisites

### System Requirements
- **OS**: macOS, Linux, or Windows with WSL2
- **RAM**: Minimum 16GB (32GB recommended for full stack)
- **Storage**: 20GB free space
- **Docker**: Docker Desktop with Docker Compose
- **Python**: 3.11+
- **Git**: Latest version

### Required Tools
```bash
# Install Docker Desktop
# https://docs.docker.com/desktop/

# Install Python 3.11+
# https://www.python.org/downloads/

# Install Git
# https://git-scm.com/downloads

# Verify installations
docker --version
python3 --version
git --version
```

## 🚀 Quick Local Setup

### 1. Clone Repository
```bash
git clone https://github.com/Rudra2018/QuantumSentinel-Nexus.git
cd QuantumSentinel-Nexus
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.template .env

# Edit configuration (use your preferred editor)
nano .env

# Required environment variables:
# SERVICE_NAME=LOCAL_DEVELOPMENT
# AWS_DEFAULT_REGION=us-east-1
# ANALYSIS_TIMEOUT=3600
# MAX_CONCURRENT_ANALYSES=3
```

### 3. Local Development Options

## 🔧 Option A: Individual Service Development

### Binary Analysis Service
```bash
cd services/binary-analysis

# Install dependencies
pip install -r requirements-simple.txt

# Run service locally
python main.py

# Test service
curl http://localhost:8008/health
```

### IBB Research Engine
```bash
cd services/ibb-research

# Install dependencies
pip install -r requirements.simple.txt

# Run comprehensive bounty engine
python comprehensive_bounty_engine.py

# Test engine
curl http://localhost:8002/health
```

### Web UI Dashboard
```bash
cd services/web-ui

# Install dependencies
pip install -r requirements.txt

# Run web interface
python main.py

# Access dashboard
open http://localhost:8080
```

## 🐳 Option B: Docker Compose (Recommended)

### Complete Stack Deployment
```bash
# Create local docker-compose file
cat > docker-compose.local.yml << 'EOF'
version: '3.8'

services:
  binary-analysis:
    build: ./services/binary-analysis
    ports:
      - "8008:8008"
    environment:
      - SERVICE_NAME=BINARY_ANALYSIS_LOCAL
      - SERVICE_PORT=8008
    volumes:
      - ./uploads:/app/uploads
    networks:
      - quantum-network

  ibb-research:
    build:
      context: ./services/ibb-research
      dockerfile: Dockerfile.simple
    ports:
      - "8002:8002"
    environment:
      - SERVICE_NAME=IBB_RESEARCH_LOCAL
      - SERVICE_PORT=8002
    depends_on:
      - binary-analysis
    networks:
      - quantum-network

  web-ui:
    build: ./services/web-ui
    ports:
      - "8080:80"
    environment:
      - BACKEND_URL=http://ibb-research:8002
    depends_on:
      - ibb-research
    networks:
      - quantum-network

  ml-intelligence:
    build: ./services/ml-intelligence
    ports:
      - "8001:8001"
    environment:
      - SERVICE_NAME=ML_INTELLIGENCE_LOCAL
    networks:
      - quantum-network

  reconnaissance:
    build: ./services/reconnaissance
    ports:
      - "8007:8007"
    environment:
      - SERVICE_NAME=RECONNAISSANCE_LOCAL
    networks:
      - quantum-network

networks:
  quantum-network:
    driver: bridge

volumes:
  uploads:
  logs:
EOF

# Start complete local stack
docker-compose -f docker-compose.local.yml up -d

# View logs
docker-compose -f docker-compose.local.yml logs -f

# Stop stack
docker-compose -f docker-compose.local.yml down
```

## 🔬 Option C: Development with Live AWS Integration

### Hybrid Local-Cloud Setup
```bash
# Use local development with cloud backend
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1

# Run local frontend with cloud backend
cd services/web-ui
export BACKEND_URL=https://2p83ibp3ai.execute-api.us-east-1.amazonaws.com/prod
python main.py

# Access hybrid setup
open http://localhost:8080
```

## 📊 Service Architecture Map

### Local Service Ports
| Service | Port | Purpose | Status |
|---------|------|---------|--------|
| **Binary Analysis** | 8008 | Advanced binary analysis & exploit development | ✅ Ready |
| **IBB Research** | 8002 | 24/7 bounty research with binary integration | ✅ Ready |
| **Web UI** | 8080 | Interactive dashboard and management | ✅ Ready |
| **ML Intelligence** | 8001 | Machine learning and AI analysis | ✅ Ready |
| **Reconnaissance** | 8007 | OSINT and information gathering | ✅ Ready |
| **Fuzzing** | 8003 | Automated fuzzing and testing | ⚡ Optional |
| **SAST-DAST** | 8005 | Static and dynamic analysis | ⚡ Optional |
| **Reporting** | 8004 | PDF report generation | ⚡ Optional |

## 🧪 Testing and Validation

### Health Checks
```bash
# Test all local services
curl http://localhost:8008/health  # Binary Analysis
curl http://localhost:8002/health  # IBB Research
curl http://localhost:8080/health  # Web UI
curl http://localhost:8001/health  # ML Intelligence
curl http://localhost:8007/health  # Reconnaissance
```

### Binary Analysis Testing
```bash
# Upload a test binary for analysis
curl -X POST http://localhost:8008/analyze/upload \
  -F "file=@/path/to/test/binary" \
  -F "analysis_depth=comprehensive" \
  -F "exploit_development=true"

# Check analysis status
curl http://localhost:8008/analysis/{analysis_id}
```

### Comprehensive Scanning Testing
```bash
# Trigger comprehensive scan
curl -X POST http://localhost:8002/scan/example.com \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "include_binary_analysis": true}'

# View discovered programs
curl http://localhost:8002/programs
```

### Web Dashboard Testing
```bash
# Access web interface
open http://localhost:8080

# Key features to test:
# - Service status monitoring
# - Binary analysis submission
# - Scan results viewing
# - Real-time updates
```

## 🔧 Development Configuration

### IDE Setup (VS Code)
```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "docker.dockerComposeDetection": "on"
}
```

### Debug Configuration
```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Binary Analysis Service",
      "type": "python",
      "request": "launch",
      "program": "services/binary-analysis/main.py",
      "console": "integratedTerminal",
      "env": {
        "SERVICE_PORT": "8008",
        "SERVICE_NAME": "BINARY_ANALYSIS_DEBUG"
      }
    },
    {
      "name": "IBB Research Engine",
      "type": "python",
      "request": "launch",
      "program": "services/ibb-research/comprehensive_bounty_engine.py",
      "console": "integratedTerminal",
      "env": {
        "SERVICE_PORT": "8002",
        "SERVICE_NAME": "IBB_RESEARCH_DEBUG"
      }
    }
  ]
}
```

## 📝 Development Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/binary-analysis-enhancement

# Make changes to binary analysis service
cd services/binary-analysis
# Edit files...

# Test locally
python main.py

# Test with Docker
docker build -t binary-analysis-dev .
docker run -p 8008:8008 binary-analysis-dev

# Commit and push
git add .
git commit -m "🔬 Enhanced binary analysis feature"
git push origin feature/binary-analysis-enhancement
```

### 2. Integration Testing
```bash
# Test full integration
docker-compose -f docker-compose.local.yml up

# Run integration tests
python -m pytest tests/integration/

# Validate API endpoints
python tests/api_validation.py
```

### 3. Performance Testing
```bash
# Load test binary analysis service
ab -n 100 -c 10 http://localhost:8008/health

# Monitor resource usage
docker stats

# Check service logs
docker-compose logs -f binary-analysis
```

## 🚀 Production Deployment

### AWS Deployment
```bash
# Deploy to AWS (requires AWS credentials)
./auto-deploy-aws.sh

# Deploy specific service
./deploy-binary-analysis.sh

# Monitor deployment
aws ecs describe-services --cluster quantumsentinel-nexus-cluster --services quantumsentinel-binary-analysis
```

### Local to Cloud Migration
```bash
# Export local configuration
docker-compose -f docker-compose.local.yml config > local-config-export.yml

# Build production images
docker build -t quantumsentinel-binary-analysis:production ./services/binary-analysis

# Tag for registry
docker tag quantumsentinel-binary-analysis:production your-registry/quantumsentinel-binary-analysis:latest

# Push to registry
docker push your-registry/quantumsentinel-binary-analysis:latest
```

## 🛠️ Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check port usage
lsof -i :8008
netstat -tulpn | grep :8008

# Kill conflicting processes
sudo kill -9 $(lsof -t -i:8008)
```

#### Docker Issues
```bash
# Clean Docker environment
docker system prune -a
docker volume prune

# Restart Docker Desktop
# (Use system tray/menu)

# Rebuild containers
docker-compose -f docker-compose.local.yml build --no-cache
```

#### Service Communication
```bash
# Test service connectivity
docker exec -it quantum_binary-analysis_1 ping ibb-research
docker exec -it quantum_ibb-research_1 curl http://binary-analysis:8008/health

# Check network configuration
docker network ls
docker network inspect quantum_quantum-network
```

#### Memory Issues
```bash
# Increase Docker memory allocation
# Docker Desktop -> Settings -> Resources -> Advanced -> Memory: 8GB+

# Monitor container memory usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Optimize resource usage
export MAX_CONCURRENT_ANALYSES=2
export ANALYSIS_TIMEOUT=1800
```

## 📚 Additional Resources

### Documentation
- [Architecture Overview](./docs/ARCHITECTURE.md)
- [API Documentation](./docs/API.md)
- [Deployment Guide](./docs/DEPLOYMENT_GUIDE.md)
- [Security Features](./SECURITY_DOCUMENTATION.md)

### Development Tools
- [VS Code Extensions](https://marketplace.visualstudio.com/items?itemName=ms-python.python)
- [Docker Desktop](https://docs.docker.com/desktop/)
- [Postman Collection](./docs/postman/QuantumSentinel-Nexus.postman_collection.json)

### Community
- [GitHub Issues](https://github.com/Rudra2018/QuantumSentinel-Nexus/issues)
- [Contributing Guide](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)

## 🎯 Quick Start Summary

1. **Clone**: `git clone https://github.com/Rudra2018/QuantumSentinel-Nexus.git`
2. **Setup**: `cp .env.template .env`
3. **Run**: `docker-compose -f docker-compose.local.yml up -d`
4. **Test**: `curl http://localhost:8008/health`
5. **Access**: `open http://localhost:8080`

You're now ready to develop and enhance the QuantumSentinel-Nexus platform locally! 🚀