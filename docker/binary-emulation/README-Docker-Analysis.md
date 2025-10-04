# QuantumSentinel-Nexus Binary Analysis Docker Environment

This directory contains specialized Docker containers for comprehensive binary analysis across multiple platforms and formats.

## 🚀 Quick Start

### Start All Analysis Containers
```bash
docker-compose -f docker-compose-comprehensive.yml --profile full up -d
```

### Start Specific Analysis Environment
```bash
# macOS binary analysis
docker-compose -f docker-compose-comprehensive.yml up quantum-macos-analysis -d

# Mobile (APK/IPA) analysis
docker-compose -f docker-compose-comprehensive.yml up quantum-mobile-analysis -d

# Windows PE analysis
docker-compose -f docker-compose-comprehensive.yml up quantum-windows-analysis -d

# Linux packages analysis
docker-compose -f docker-compose-comprehensive.yml up quantum-linux-packages -d
```

## 📦 Available Containers

### 1. General Purpose Analysis
- **quantum-binary-analysis**: Full Ubuntu environment with comprehensive tools
- **quantum-binary-minimal**: Lightweight Alpine for quick analysis

### 2. Platform-Specific Analysis

#### macOS Binary Analysis (`quantum-macos-analysis`)
- **Supported formats**: Mach-O, .app bundles, KEXT, dylib, frameworks
- **Tools**: jtool2, cctools, radare2, LIEF, class-dump
- **Analysis script**: `analyze-macos-binary.sh`

#### Windows Binary Analysis (`quantum-windows-analysis`)
- **Supported formats**: PE, EXE, DLL, MSI, SYS, SCR, COM
- **Tools**: WINE, pefile, radare2, YARA, cutter
- **VNC access**: Port 5900 for GUI applications
- **Analysis script**: `analyze-pe-binary.sh`

#### Mobile Binary Analysis (`quantum-mobile-analysis`)
- **Supported formats**: APK, IPA, AAB, DEX
- **Android tools**: apktool, jadx, dex2jar, androguard
- **iOS tools**: class-dump, biplist, pyimg4
- **Analysis scripts**: `analyze-apk.sh`, `analyze-ipa.sh`

#### Linux Package Analysis (`quantum-linux-packages`)
- **Supported formats**: DEB, RPM, kernel modules (.ko), SNAP, AppImage
- **Tools**: Ghidra, volatility3, binwalk, alien
- **Analysis scripts**: `analyze-deb-package.sh`, `analyze-kernel-module.sh`

### 3. Supporting Services
- **quantum-ml-analysis**: Machine learning vulnerability detection
- **quantum-network-monitor**: Network traffic monitoring for dynamic analysis
- **quantum-analysis-coordinator**: Distributed analysis coordination
- **quantum-report-generator**: PDF/HTML report generation
- **quantum-dashboard**: Web-based analysis dashboard

## 🛠 Usage Examples

### Analyze an APK File
```bash
# Start mobile analysis container
docker-compose -f docker-compose-comprehensive.yml up quantum-mobile-analysis -d

# Copy APK to analysis directory
cp /path/to/app.apk docker/binary-emulation/binaries/

# Run analysis
docker exec -it quantum-mobile-analysis /usr/local/bin/analyze-apk.sh /analysis/binaries/app.apk

# Check results
docker exec -it quantum-mobile-analysis ls /analysis/results/
```

### Analyze a Windows PE Binary
```bash
# Start Windows analysis container
docker-compose -f docker-compose-comprehensive.yml up quantum-windows-analysis -d

# Copy binary to analysis directory
cp /path/to/binary.exe docker/binary-emulation/binaries/

# Run analysis
docker exec -it quantum-windows-analysis /usr/local/bin/analyze-pe-binary.sh /analysis/binaries/binary.exe

# Access via VNC for GUI tools (optional)
# Connect VNC viewer to localhost:5900
```

### Analyze a macOS Application
```bash
# Start macOS analysis container
docker-compose -f docker-compose-comprehensive.yml up quantum-macos-analysis -d

# Copy application to analysis directory
cp -r /path/to/App.app docker/binary-emulation/binaries/

# Run analysis
docker exec -it quantum-macos-analysis /usr/local/bin/analyze-macos-binary.sh /analysis/binaries/App.app
```

### Analyze a Linux Package
```bash
# Start package analysis container
docker-compose -f docker-compose-comprehensive.yml up quantum-linux-packages -d

# Copy package to analysis directory
cp /path/to/package.deb docker/binary-emulation/binaries/

# Run analysis
docker exec -it quantum-linux-packages /usr/local/bin/analyze-deb-package.sh /analysis/binaries/package.deb
```

## 📊 Dashboard Access

Access the analysis dashboard at: http://localhost:3000

The dashboard provides:
- Real-time analysis status
- Historical analysis results
- Visual vulnerability reports
- Analysis queue management

## 📈 Report Generation

Generate comprehensive reports:
```bash
# Access report generator
curl -X POST http://localhost:8080/generate-report \
  -H "Content-Type: application/json" \
  -d '{"analysis_id": "your-analysis-id", "format": "pdf"}'
```

## 🔧 Configuration

### Environment Variables

Each container supports these environment variables:
- `ANALYSIS_MODE`: Type of analysis (full, static, dynamic)
- `TIMEOUT`: Analysis timeout in seconds
- `SUPPORTED_FORMATS`: Comma-separated list of supported formats

### Volume Mounts

- `./binaries`: Input binaries (read-only)
- `./results`: Analysis results (read-write)
- `./configs`: Configuration files (read-only)
- `./scripts`: Analysis scripts (read-only)

### Persistent Storage

Format-specific workspaces are persisted:
- `volumes/wine-data`: Windows WINE environment
- `volumes/macos-workspace`: macOS analysis workspace
- `volumes/mobile-workspace`: Mobile analysis workspace
- `volumes/packages-workspace`: Package analysis workspace

## 🔐 Security Considerations

### Container Isolation
- Each analysis runs in isolated containers
- Network segmentation via Docker networks
- Capability restrictions where possible

### Malware Analysis
- Use `quantum-network-monitor` for network activity monitoring
- Enable logging for all container activities
- Consider additional sandboxing for unknown binaries

### Resource Limits
Add resource limits to docker-compose.yml:
```yaml
services:
  quantum-binary-analysis:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
```

## 🐛 Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose -f docker-compose-comprehensive.yml logs quantum-macos-analysis

# Rebuild container
docker-compose -f docker-compose-comprehensive.yml build --no-cache quantum-macos-analysis
```

### Analysis Script Fails
```bash
# Enter container for debugging
docker exec -it quantum-mobile-analysis /bin/bash

# Check tool availability
which apktool jadx dex2jar

# Run script manually with debug
bash -x /usr/local/bin/analyze-apk.sh /analysis/binaries/test.apk
```

### VNC Connection Issues (Windows Container)
```bash
# Check VNC server status
docker exec -it quantum-windows-analysis ps aux | grep vnc

# Restart VNC
docker exec -it quantum-windows-analysis /home/win-analyst/start-vnc.sh
```

## 📁 Directory Structure

```
docker/binary-emulation/
├── Dockerfile.macos-analysis          # macOS binary analysis
├── Dockerfile.mobile-analysis         # Mobile (APK/IPA) analysis
├── Dockerfile.linux-packages          # Linux package analysis
├── Dockerfile.windows-enhanced        # Windows PE analysis
├── Dockerfile.ubuntu-x64              # General purpose analysis
├── Dockerfile.alpine-minimal          # Lightweight analysis
├── docker-compose-comprehensive.yml   # Complete orchestration
├── scripts/                           # Analysis scripts
│   ├── analyze-macos-binary.sh
│   ├── analyze-apk.sh
│   ├── analyze-pe-binary.sh
│   └── ...
├── binaries/                          # Input binaries
├── results/                           # Analysis results
├── configs/                           # Configuration files
└── volumes/                           # Persistent storage
    ├── wine-data/
    ├── macos-workspace/
    ├── mobile-workspace/
    └── ...
```

## 🔄 Integration with QuantumSentinel

The Docker environment integrates with the main QuantumSentinel platform:

1. **CLI Integration**: Use `quantum_cli.py --docker` flag
2. **Web UI**: Upload binaries via web interface
3. **API Integration**: REST API endpoints for analysis
4. **ML Integration**: Automatic ML analysis via coordinator

## 📝 Analysis Output

Each analysis generates:
- **JSON metadata**: Structured analysis results
- **Security assessment**: Risk scoring and vulnerability identification
- **Evidence collection**: Screenshots, logs, extracted files
- **Comprehensive reports**: PDF/HTML reports with findings

## 🎯 Best Practices

1. **Resource Management**: Monitor container resource usage
2. **Security**: Regularly update base images and tools
3. **Backup**: Regularly backup analysis results and configurations
4. **Logging**: Enable comprehensive logging for audit trails
5. **Testing**: Test containers with known samples before production use

## 📞 Support

For issues or questions:
1. Check container logs: `docker-compose logs [service-name]`
2. Review analysis scripts in `scripts/` directory
3. Consult main QuantumSentinel documentation
4. Submit issues via the project repository