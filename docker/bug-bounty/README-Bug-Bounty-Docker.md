# QuantumSentinel-Nexus Bug Bounty Docker Environment

This Docker environment provides a comprehensive bug bounty automation platform with OWASP ZAP integration, browser automation, and reconnaissance capabilities.

## 🚀 Quick Start

### Start Full Bug Bounty Environment
```bash
# Clone and navigate to bug bounty docker directory
cd docker/bug-bounty

# Create environment file
cp .env.example .env
# Edit .env with your API keys

# Start all services
docker-compose -f docker-compose-bounty.yml up -d

# View logs
docker-compose -f docker-compose-bounty.yml logs -f quantum-bounty-scanner
```

### Quick Scan Example
```bash
# Start quick scan profile for a target
docker-compose -f docker-compose-bounty.yml --profile quick up \
    -e TARGET=example.com \
    -e PLATFORM=hackerone \
    quantum-bounty-quick

# Or run a single command scan
docker run --rm \
    -e TARGET=example.com \
    -e CHAOS_API_KEY=your-key \
    -v $(pwd)/results:/bounty/results \
    quantum-bounty-scanner
```

## 📦 Available Services

### Core Services

#### 1. **quantum-bounty-scanner**
Main bug bounty scanning service with comprehensive automation.
- **Purpose**: Full bug bounty workflow automation
- **Features**: Platform integration, reconnaissance, ZAP scanning
- **Ports**: 8080 (health check)
- **Volumes**: `./results:/bounty/results`

#### 2. **quantum-zap-proxy**
OWASP ZAP proxy for dynamic application security testing.
- **Purpose**: DAST scanning and vulnerability detection
- **Features**: Spider, AJAX spider, active scanning, API
- **Ports**: 8080 (ZAP UI), 8090 (Proxy)
- **Volumes**: `./zap-results:/zap/wrk/output`

#### 3. **quantum-recon**
Specialized reconnaissance service for asset discovery.
- **Purpose**: Subdomain enumeration and asset discovery
- **Features**: Chaos API, Subfinder, Amass, HTTP probing
- **Tools**: subfinder, httpx, nuclei, dnsx, assetfinder
- **Volumes**: `./recon-results:/recon/results`

#### 4. **quantum-browser-automation**
Browser automation for context-aware testing.
- **Purpose**: Automated browser interactions through ZAP proxy
- **Features**: Selenium Grid integration, screenshot capture
- **Supports**: Chrome, Firefox via Selenium Grid
- **Volumes**: `./browser-results:/automation/results`

### Supporting Services

#### 5. **selenium-hub / selenium-chrome / selenium-firefox**
Selenium Grid for distributed browser automation.
- **Purpose**: Scalable browser automation infrastructure
- **Features**: Multi-browser support, session management
- **Ports**: 4444 (Grid Hub)

#### 6. **quantum-db**
PostgreSQL database for storing scan results and program data.
- **Purpose**: Persistent storage for scan data
- **Features**: Automated schema initialization
- **Volumes**: `quantum-db-data:/var/lib/postgresql/data`

#### 7. **quantum-redis**
Redis for caching and job queuing.
- **Purpose**: High-performance caching and task queue
- **Features**: Persistence, authentication
- **Volumes**: `quantum-redis-data:/data`

#### 8. **quantum-dashboard**
Web dashboard for monitoring and control.
- **Purpose**: Real-time monitoring and scan management
- **Features**: Live updates, scan history, reporting
- **Ports**: 3000 (Web UI)

## 🎯 Scanning Profiles

### Comprehensive Profile (Default)
```bash
docker-compose -f docker-compose-bounty.yml up quantum-bounty-scanner
```
- Full reconnaissance (subdomains, ports, tech stack)
- Context-aware browser testing
- Comprehensive ZAP DAST scanning
- OWASP Top 10 vulnerability detection

### Quick Profile
```bash
docker-compose -f docker-compose-bounty.yml --profile quick up quantum-bounty-quick
```
- Basic reconnaissance
- Limited spider depth (2 levels)
- Quick ZAP scanning
- Faster results (~30 minutes)

### Passive Profile
```bash
docker-compose -f docker-compose-bounty.yml --profile passive up quantum-bounty-passive
```
- Reconnaissance only
- Passive ZAP scanning
- No active vulnerability testing
- Stealth mode

## 🌐 Platform-Specific Scanning

### HackerOne
```bash
docker-compose -f docker-compose-bounty.yml --profile hackerone up \
    -e TARGET=example.com \
    -e PROGRAM=example-program \
    quantum-hackerone
```

### Bugcrowd
```bash
docker-compose -f docker-compose-bounty.yml --profile bugcrowd up \
    -e TARGET=api.example.com \
    -e PROGRAM=example-program \
    quantum-bugcrowd
```

### Huntr
```bash
docker-compose -f docker-compose-bounty.yml --profile huntr up \
    -e TARGET=github.com/owner/repo \
    quantum-huntr
```

## ⚙️ Configuration

### Environment Variables

Create `.env` file with the following variables:

```bash
# API Keys
CHAOS_API_KEY=1545c524-7e20-4b62-aa4a-8235255cff96
SHODAN_API_KEY=your-shodan-key
CENSYS_API_ID=your-censys-id
CENSYS_API_SECRET=your-censys-secret

# Database
DB_PASSWORD=quantum_secure_password_2024
REDIS_PASSWORD=quantum_redis_password

# Scanning Configuration
SCAN_MODE=comprehensive
ZAP_MEMORY=2g
SUBDOMAIN_THREADS=50
BROWSER_TIMEOUT=300

# Platform Specific
TARGET=
PLATFORM=
PROGRAM=
```

### Volume Mounts

The following directories are mounted for data persistence:

```
./configs/          → Container configurations
./scripts/          → Custom scripts
./results/          → Scan results and reports
./zap-results/      → ZAP scan outputs
./recon-results/    → Reconnaissance data
./browser-results/  → Browser automation results
./wordlists/        → Custom wordlists
```

## 📊 Usage Examples

### 1. Complete Bug Bounty Assessment
```bash
# Start full environment
docker-compose -f docker-compose-bounty.yml up -d

# Run comprehensive scan
docker exec quantum-bounty-scanner python3 /opt/quantumsentinel/quantum_cli.py bounty scan \
    --asset example.com \
    --platform hackerone \
    --types recon,context,dast \
    --chaos-api \
    --zap-profile comprehensive
```

### 2. Reconnaissance Only
```bash
# Start recon service
docker-compose -f docker-compose-bounty.yml up quantum-recon

# Run reconnaissance
docker exec quantum-recon python3 /opt/quantumsentinel/quantum_cli.py bounty recon \
    --target example.com \
    --chaos-api \
    --deep
```

### 3. ZAP DAST Scanning
```bash
# Start ZAP and browser automation
docker-compose -f docker-compose-bounty.yml up quantum-zap-proxy selenium-hub selenium-chrome

# Run ZAP scan
docker exec quantum-bounty-scanner python3 /opt/quantumsentinel/quantum_cli.py bounty zap-scan \
    --target https://example.com \
    --profile comprehensive \
    --ajax-spider \
    --formats json,html,xml
```

### 4. Platform Program Discovery
```bash
# Discover HackerOne programs
docker exec quantum-bounty-scanner python3 /opt/quantumsentinel/quantum_cli.py bounty programs \
    --platform hackerone \
    --active-only \
    --output hackerone_programs.json

# Extract assets from specific program
docker exec quantum-bounty-scanner python3 /opt/quantumsentinel/quantum_cli.py bounty assets \
    --program "example-program" \
    --platform hackerone \
    --output program_assets.json
```

## 🔧 Advanced Configuration

### Custom ZAP Scripts
Place custom ZAP scripts in `./zap-scripts/`:
```bash
./zap-scripts/
├── authentication.js
├── custom-scan-rules.js
└── post-processing.py
```

### Custom Wordlists
Add custom wordlists to `./wordlists/`:
```bash
./wordlists/
├── custom-subdomains.txt
├── api-endpoints.txt
└── parameters.txt
```

### Platform Configurations
Customize platform settings in `./configs/`:
```bash
./configs/
├── hackerone.yaml
├── bugcrowd.yaml
├── huntr.yaml
└── general.yaml
```

## 📈 Monitoring and Reporting

### Dashboard Access
Access the web dashboard at: http://localhost:3000

### ZAP Interface
Access ZAP web interface at: http://localhost:8080

### Health Checks
```bash
# Check service health
curl http://localhost:8080/health

# Check all services
docker-compose -f docker-compose-bounty.yml ps
```

### Logs
```bash
# View all logs
docker-compose -f docker-compose-bounty.yml logs -f

# View specific service logs
docker-compose -f docker-compose-bounty.yml logs -f quantum-bounty-scanner
docker-compose -f docker-compose-bounty.yml logs -f quantum-zap-proxy
```

## 🔐 Security Considerations

### Network Isolation
All services run in isolated Docker network `bounty-network` (172.20.0.0/16).

### Resource Limits
Add resource limits for production use:
```yaml
services:
  quantum-bounty-scanner:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          memory: 2G
```

### API Key Management
- Store API keys in `.env` file (gitignored)
- Use Docker secrets for production
- Rotate keys regularly

### Data Protection
- Scan results contain sensitive information
- Use appropriate file permissions
- Consider encryption for persistent volumes

## 🛠 Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker-compose -f docker-compose-bounty.yml logs quantum-bounty-scanner

# Rebuild container
docker-compose -f docker-compose-bounty.yml build --no-cache quantum-bounty-scanner
```

#### ZAP Proxy Connection Issues
```bash
# Check ZAP proxy status
curl http://localhost:8080/health

# Restart ZAP
docker-compose -f docker-compose-bounty.yml restart quantum-zap-proxy
```

#### Browser Automation Failures
```bash
# Check Selenium Grid
curl http://localhost:4444/wd/hub/status

# Scale browser nodes
docker-compose -f docker-compose-bounty.yml up --scale selenium-chrome=4
```

#### Database Connection Issues
```bash
# Check database status
docker exec quantum-db pg_isready

# View database logs
docker-compose -f docker-compose-bounty.yml logs quantum-db
```

### Performance Tuning

#### Memory Optimization
```bash
# Increase ZAP memory
export ZAP_MEMORY=4g

# Reduce browser instances
export NODE_MAX_INSTANCES=2
```

#### Network Optimization
```bash
# Increase subdomain threads
export SUBDOMAIN_THREADS=100

# Adjust timeouts
export BROWSER_TIMEOUT=600
```

## 📝 Best Practices

1. **Resource Management**: Monitor container resource usage regularly
2. **Security**: Keep images updated and scan for vulnerabilities
3. **Backup**: Regularly backup scan results and configurations
4. **Logging**: Enable comprehensive logging for audit trails
5. **Testing**: Test containers with known samples before production

## 🎯 Integration with QuantumSentinel

This Docker environment integrates seamlessly with the main QuantumSentinel platform:

1. **CLI Integration**: Use `--docker` flag for containerized scans
2. **Web UI**: Upload targets via web interface
3. **API Integration**: REST API endpoints for automation
4. **Report Generation**: Automatic bug bounty specific reports

## 📞 Support

For issues or questions:
1. Check container logs: `docker-compose logs [service-name]`
2. Review configurations in `configs/` directory
3. Consult main QuantumSentinel documentation
4. Submit issues via the project repository

## 🔄 Updates and Maintenance

### Updating Tools
```bash
# Update all containers
docker-compose -f docker-compose-bounty.yml pull
docker-compose -f docker-compose-bounty.yml up -d --force-recreate

# Update specific tools within containers
docker exec quantum-recon nuclei -update-templates
```

### Cleanup
```bash
# Stop and remove all containers
docker-compose -f docker-compose-bounty.yml down

# Remove volumes (WARNING: This deletes all data)
docker-compose -f docker-compose-bounty.yml down -v

# Clean up unused images
docker system prune -a
```