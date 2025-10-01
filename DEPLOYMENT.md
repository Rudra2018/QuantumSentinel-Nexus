# 🚀 QuantumSentinel-Nexus Deployment Guide

## Local Development Setup

### Prerequisites
- Python 3.8+
- 4GB+ RAM
- 10GB+ disk space
- Docker (optional, for DAST testing)

### Installation Steps

1. **Clone Repository**
```bash
git clone https://github.com/your-username/quantumsentinel-nexus.git
cd quantumsentinel-nexus
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Create Required Directories**
```bash
mkdir -p uploads assessments reports logs
```

4. **Start Services**
```bash
# Start main dashboard
python3 unified_security_dashboard_simple.py

# Access at: http://localhost:8160
```

## Production Deployment

### Docker Deployment

```bash
# Build image
docker build -t quantumsentinel-nexus .

# Run container
docker run -d -p 8160:8160 -v $(pwd)/uploads:/app/uploads quantumsentinel-nexus
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quantumsentinel-nexus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: quantumsentinel-nexus
  template:
    metadata:
      labels:
        app: quantumsentinel-nexus
    spec:
      containers:
      - name: quantumsentinel-nexus
        image: quantumsentinel-nexus:latest
        ports:
        - containerPort: 8160
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Web server port | 8160 |
| `UPLOAD_FOLDER` | File upload directory | uploads/ |
| `MAX_CONTENT_LENGTH` | Max upload size | 500MB |
| `SECRET_KEY` | Flask secret key | auto-generated |

### Security Considerations

- Run with non-root user
- Enable HTTPS in production
- Configure firewall rules
- Regular security updates
- Monitor resource usage

## Performance Tuning

### Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Web Dashboard | 1 core | 1GB | 1GB |
| SAST Engine | 2 cores | 2GB | 5GB |
| DAST Engine | 2 cores | 4GB | 10GB |
| ML Intelligence | 4 cores | 8GB | 20GB |

### Optimization Tips

- Use SSD storage for better I/O
- Increase worker processes for high load
- Configure Redis for caching
- Use CDN for static assets
