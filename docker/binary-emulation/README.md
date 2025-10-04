# QuantumSentinel Binary Emulation Environment

Docker-based binary analysis and emulation platform for secure cross-platform binary security assessment.

## Overview

This module provides containerized environments for analyzing and emulating binaries across multiple architectures and platforms. Each environment is optimized for specific analysis scenarios while maintaining security isolation.

## Environments

### 1. Ubuntu x64 Full Environment (`Dockerfile.ubuntu-x64`)
**Purpose**: Comprehensive binary analysis with full toolchain

**Features**:
- Multi-architecture QEMU emulation (x86, x64, ARM, MIPS, PPC)
- Advanced debugging tools (GDB, Radare2, pwndbg)
- Binary analysis frameworks (angr, pwntools, frida)
- Network monitoring capabilities
- Python ML libraries for vulnerability detection

**Use Cases**:
- Complete malware analysis
- Reverse engineering complex binaries
- Vulnerability research
- Exploit development

### 2. Alpine Minimal Environment (`Dockerfile.alpine-minimal`)
**Purpose**: Lightweight analysis for resource-constrained scenarios

**Features**:
- Essential binary analysis tools
- Basic QEMU support
- Minimal Python environment
- Fast startup and low memory usage

**Use Cases**:
- Quick binary triage
- CI/CD integration
- Batch processing
- IOT device analysis

### 3. Windows WINE Environment (`Dockerfile.windows-wine`)
**Purpose**: Windows PE binary analysis and execution

**Features**:
- WINE Windows emulation layer
- PE-specific analysis tools
- Windows debugging utilities
- Registry and process monitoring
- Headless execution with Xvfb

**Use Cases**:
- Windows malware analysis
- PE format research
- Legacy Windows application analysis
- Cross-platform compatibility testing

## Quick Start

### Build All Environments
```bash
cd docker/binary-emulation
docker-compose build
```

### Run Full Analysis Environment
```bash
docker-compose run quantum-binary-analysis
```

### Analyze a Binary
```bash
# Copy binary to analysis directory
cp /path/to/binary ./binaries/

# Run comprehensive analysis
docker-compose run quantum-binary-analysis \
  analyze-binary.sh --tools all ./binaries/sample.bin

# Run Windows PE analysis
docker-compose run quantum-binary-windows \
  analyze-windows.sh ./binaries/malware.exe

# Run minimal analysis
docker-compose run quantum-binary-minimal \
  analyze-minimal.sh ./binaries/sample.elf
```

## Analysis Scripts

### `analyze-binary.sh`
Comprehensive multi-tool binary analysis
- **Static Analysis**: File info, disassembly, strings, entropy
- **Dynamic Analysis**: Strace, ltrace, QEMU emulation
- **ML Analysis**: Vulnerability pattern detection
- **Formats**: ELF, PE, Mach-O, raw binaries

```bash
analyze-binary.sh [OPTIONS] BINARY_PATH

Options:
  --tools TOOLS     Analysis tools: all, static, dynamic, ml
  --timeout SEC     Analysis timeout (default: 300s)
  --output DIR      Output directory
  --verbose         Enable verbose logging
```

### `emulate-binary.sh`
Safe binary execution with monitoring
- **Multi-architecture**: Auto-detection or manual specification
- **Sandbox Mode**: Isolated execution environment
- **Monitoring**: Network, filesystem, system calls
- **Time Control**: Configurable execution timeout

```bash
emulate-binary.sh [OPTIONS] BINARY_PATH

Options:
  --time SEC        Emulation time (default: 30s)
  --arch ARCH       Force architecture (x86, x64, arm, mips)
  --network         Monitor network activity
  --files           Monitor filesystem activity
  --no-sandbox      Disable sandbox (DANGEROUS)
```

### `wine-runner.sh`
Windows binary execution with WINE
- **PE Execution**: Windows binary execution on Linux
- **Registry Monitoring**: Track registry changes
- **Process Monitoring**: Monitor spawned processes
- **Network Analysis**: Capture network traffic

```bash
wine-runner.sh [OPTIONS] BINARY_PATH

Options:
  --time SEC        Execution time (default: 30s)
  --arch ARCH       Wine architecture (win32, win64)
  --network         Monitor network activity
  --registry        Monitor registry changes
```

## Security Features

### Sandboxing
- **Container Isolation**: Full Docker containerization
- **Chroot Environments**: Additional filesystem isolation
- **Network Segregation**: Isolated network namespaces
- **Resource Limits**: CPU and memory constraints

### Monitoring
- **System Calls**: Complete strace/ltrace logging
- **Network Traffic**: Full packet capture with tcpdump
- **File Operations**: inotify-based filesystem monitoring
- **Process Tracking**: Process creation and termination

### Safety Measures
- **Timeout Protection**: Automatic termination of long-running processes
- **Non-root Execution**: Analysis runs under dedicated user account
- **Read-only Binaries**: Input binaries mounted read-only
- **Cleanup Procedures**: Automatic cleanup on exit

## Configuration

### GDB Configuration (`configs/gdbinit`)
Enhanced debugging environment with:
- Custom vulnerability analysis commands
- Memory layout inspection
- Exploit development helpers
- Python scripting integration

### Docker Compose
Orchestrated multi-container environment with:
- Shared volumes for data exchange
- Network isolation
- Service dependencies
- Resource management

## Integration

### QuantumSentinel CLI
```bash
# Analyze binary with Docker backend
quantum analyze binary --docker --env ubuntu ./sample.bin

# Run in minimal environment
quantum analyze binary --docker --env alpine ./sample.bin

# Windows analysis
quantum analyze binary --docker --env windows ./malware.exe
```

### API Integration
```python
from quantum.engines.binary_docker import DockerBinaryEngine

engine = DockerBinaryEngine()
result = engine.analyze(
    binary_path="./sample.bin",
    environment="ubuntu",
    analysis_type="full"
)
```

## Output Structure

```
results/
├── analysis_BINARY_TIMESTAMP/
│   ├── static/
│   │   ├── file_info.txt
│   │   ├── disassembly.txt
│   │   ├── elf_analysis.txt
│   │   └── strings.txt
│   ├── dynamic/
│   │   ├── strace.txt
│   │   ├── ltrace.txt
│   │   └── network.pcap
│   ├── logs/
│   │   ├── analysis.log
│   │   └── emulation.log
│   └── reports/
│       ├── analysis_report.txt
│       └── ml_analysis.json
```

## Supported Architectures

- **x86**: 32-bit Intel/AMD
- **x86-64**: 64-bit Intel/AMD
- **ARM**: 32-bit ARM
- **ARM64**: 64-bit ARM (AArch64)
- **MIPS**: 32-bit MIPS
- **MIPS64**: 64-bit MIPS
- **PowerPC**: 32-bit PowerPC
- **PowerPC64**: 64-bit PowerPC

## Requirements

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum (8GB recommended)
- 10GB disk space for images
- Linux host for full QEMU support

## Troubleshooting

### Common Issues

1. **QEMU not working**: Ensure kernel supports user-mode emulation
2. **Wine crashes**: Check X11 forwarding and display settings
3. **Permission errors**: Verify volume mount permissions
4. **Network monitoring fails**: Ensure CAP_NET_RAW capability

### Debug Mode
```bash
# Enable verbose logging
docker-compose run -e VERBOSE=true quantum-binary-analysis

# Access container shell
docker-compose run quantum-binary-analysis /bin/bash

# Check logs
docker-compose logs quantum-binary-analysis
```

## Security Notice

⚠️ **Warning**: This environment is designed for malware analysis and may execute potentially dangerous code. Always:
- Run in isolated environments
- Monitor network connections
- Use dedicated analysis machines
- Follow responsible disclosure practices

## Contributing

To add new analysis tools or environments:
1. Extend the appropriate Dockerfile
2. Add analysis scripts to `scripts/`
3. Update docker-compose.yml if needed
4. Test with sample binaries
5. Update documentation