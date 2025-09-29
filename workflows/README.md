# QuantumSentinel-Nexus Security Testing Workflows

## Overview

This directory contains comprehensive security testing workflows that implement the complete HackTricks methodology. Each workflow is designed to automate specific aspects of security assessment, from mobile application analysis to network infrastructure scanning.

## 🚀 Quick Start

### Master Launcher (Recommended)
Run the complete security assessment platform:

```bash
cd /Users/ankitthakur/Downloads/QuantumSentinel-Nexus/workflows

# Complete assessment of multiple targets
python3 quantum-sentinel-launcher.py --targets example.com 192.168.1.0/24 mobile-app

# Quick web assessment only
python3 quantum-sentinel-launcher.py --targets example.com --no-mobile --no-network --assessment-type quick

# Comprehensive assessment with all modules
python3 quantum-sentinel-launcher.py --targets example.com 10.0.0.0/24 --assessment-type comprehensive
```

## 📱 Individual Workflows

### 1. Mobile Application Security Testing

**File**: `mobile-app-analysis.py`

Complete mobile application security testing workflow including APK/IPA analysis, static/dynamic analysis, and vulnerability assessment.

**Features**:
- Android APK analysis with Androguard
- iOS IPA analysis capabilities
- Static analysis (permissions, manifest, certificates)
- Dynamic analysis preparation (Frida integration)
- OWASP Mobile Top 10 coverage
- Risk scoring and reporting

**Usage**:
```bash
python3 mobile-app-analysis.py
```

**Output**: `/tmp/mobile_apps/mobile_analysis_summary.json`

### 2. Network Infrastructure Scanning

**File**: `network-scanning.py`

Comprehensive network discovery, port scanning, service enumeration, and vulnerability assessment.

**Features**:
- Host discovery (ping, nmap)
- Port scanning (TCP/UDP)
- Service enumeration and version detection
- Vulnerability scanning with Nuclei and Nmap scripts
- Custom vulnerability checks
- Risk assessment and reporting

**Usage**:
```bash
python3 network-scanning.py

# Or with custom targets
python3 -c "
import asyncio
from network_scanning import NetworkWorkflowOrchestrator

async def main():
    orchestrator = NetworkWorkflowOrchestrator()
    results = await orchestrator.run_complete_network_scan([
        '192.168.1.0/24',
        '10.0.0.1-10.0.0.50',
        '172.16.1.1'
    ])

asyncio.run(main())
"
```

**Output**: `/tmp/network_scans/network_assessment_summary.json`

### 3. Web Application Reconnaissance

**File**: `web-reconnaissance.py`

Complete web application reconnaissance including domain enumeration, subdomain discovery, technology detection, and attack surface analysis.

**Features**:
- DNS enumeration and WHOIS lookup
- Subdomain discovery (brute force, certificate transparency, search engines)
- Web crawling and endpoint discovery
- Technology stack identification
- SSL/TLS certificate analysis
- Attack surface scoring

**Usage**:
```bash
python3 web-reconnaissance.py

# Or with custom domains
python3 -c "
import asyncio
from web_reconnaissance import WebReconnaissanceOrchestrator

async def main():
    orchestrator = WebReconnaissanceOrchestrator()
    results = await orchestrator.run_complete_reconnaissance([
        'example.com',
        'testphp.vulnweb.com'
    ])

asyncio.run(main())
"
```

**Output**: `/tmp/web_recon/web_reconnaissance_summary.json`

### 4. Bug Bounty Mobile App Collection

**File**: `bug-bounty-app-collector.py`

Automated collection of mobile applications from bug bounty programs for security testing.

**Features**:
- Collection from HackerOne, Bugcrowd, Intigriti programs
- Mobile app target extraction
- APK/IPA download coordination
- Analysis dataset preparation
- Bug bounty program metadata

**Usage**:
```bash
python3 bug-bounty-app-collector.py
```

**Output**: `/tmp/bug_bounty_apps/bug_bounty_collection_report.json`

## 🔧 Configuration and Dependencies

### Python Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

**Key dependencies**:
- `aiohttp` - Async HTTP client
- `aiofiles` - Async file operations
- `dnspython` - DNS operations
- `whois` - WHOIS lookups
- `androguard` - Android APK analysis
- `frida` - Dynamic instrumentation
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing

### System Dependencies

Ensure these tools are installed:

**Network Scanning**:
```bash
# Ubuntu/Debian
sudo apt-get install nmap masscan netcat-openbsd

# macOS
brew install nmap masscan netcat
```

**Web Security**:
```bash
# Install Nuclei
wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Install FFuF
wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz
tar -xzf ffuf_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/
```

**Mobile Analysis**:
```bash
# Android SDK tools
sudo apt-get install android-tools-adb android-tools-fastboot

# Java for Android analysis
sudo apt-get install default-jdk
```

## 📊 HackTricks Methodology Coverage

### Web Application Security Testing
| Category | Techniques Covered | Tools Used |
|----------|-------------------|------------|
| **Information Gathering** | Subdomain enumeration, technology identification, directory discovery | dnspython, requests, ffuf, gobuster |
| **Authentication Testing** | Login brute force, default credentials, session analysis | nuclei, custom scripts |
| **Input Validation** | SQL injection, XSS, XXE, command injection | sqlmap, nuclei, wapiti3 |
| **File Upload Testing** | Unrestricted upload, path traversal, content-type bypass | nuclei, custom testing |
| **Business Logic** | Race conditions, privilege escalation, workflow bypass | selenium, custom scripts |
| **SSRF Testing** | Internal network scanning, metadata access, protocol abuse | nuclei, custom tools |

### Mobile Application Security
| Category | Techniques Covered | Tools Used |
|----------|-------------------|------------|
| **Static Analysis** | Manifest analysis, permission review, certificate inspection | androguard, aapt |
| **Dynamic Analysis** | Runtime manipulation, API monitoring, SSL pinning bypass | frida, objection |
| **Data Storage** | Local storage analysis, keychain inspection, backup analysis | adb, custom scripts |
| **Network Communication** | Traffic interception, certificate validation, protocol analysis | mitmproxy, frida |
| **Platform Interaction** | Deep link testing, IPC analysis, URL scheme abuse | adb, frida |

### Network Infrastructure Testing
| Category | Techniques Covered | Tools Used |
|----------|-------------------|------------|
| **Network Discovery** | Host enumeration, port scanning, service detection | nmap, masscan |
| **Service Analysis** | Version detection, banner grabbing, script scanning | nmap, custom tools |
| **Vulnerability Assessment** | CVE detection, configuration analysis, exploit verification | nuclei, nmap scripts |
| **Protocol Testing** | SSL/TLS analysis, DNS enumeration, SNMP testing | nmap, custom tools |

## 🎯 Advanced Usage Examples

### Example 1: Complete Enterprise Assessment

```bash
# Assess an entire organization
python3 quantum-sentinel-launcher.py \
    --targets example.com *.example.com 192.168.0.0/16 \
    --assessment-type comprehensive \
    --output-dir /tmp/enterprise_assessment \
    --verbose
```

### Example 2: Bug Bounty Focused Assessment

```bash
# Focus on bug bounty targets
python3 quantum-sentinel-launcher.py \
    --targets hackerone.com uber.com \
    --assessment-type standard \
    --output-dir /tmp/bugbounty_assessment
```

### Example 3: Mobile-Only Assessment

```bash
# Mobile app security testing only
python3 quantum-sentinel-launcher.py \
    --targets "mobile-apps" \
    --no-network --no-web \
    --assessment-type comprehensive \
    --output-dir /tmp/mobile_assessment
```

### Example 4: Network Infrastructure Only

```bash
# Network infrastructure assessment
python3 quantum-sentinel-launcher.py \
    --targets 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
    --no-mobile --no-web --no-bug-bounty \
    --assessment-type comprehensive \
    --output-dir /tmp/network_assessment
```

## 📋 Output Structure

```
/tmp/quantum_sentinel_results/
├── ASSESSMENT_SUMMARY.md              # Executive summary
├── quantum_sentinel_master_report.json # Complete results
├── bug_bounty_apps/                   # Bug bounty collection results
│   ├── bug_bounty_collection_report.json
│   ├── analysis_dataset.json
│   └── *.apk / *.ipa                  # Downloaded apps
├── web_reconnaissance/                # Web recon results
│   ├── web_reconnaissance_summary.json
│   └── web_recon_*.json              # Per-domain results
├── network_scanning/                  # Network scan results
│   ├── network_assessment_summary.json
│   └── network_scan_*.json           # Per-target results
└── mobile_analysis/                   # Mobile analysis results
    ├── mobile_analysis_summary.json
    └── individual app analysis files
```

## 🔍 Integration with SAST/DAST Service

All workflows integrate with the enhanced SAST/DAST service running on port 8001:

```bash
# Start the SAST/DAST service
cd /Users/ankitthakur/Downloads/QuantumSentinel-Nexus/services/sast-dast
uvicorn main:app --host 0.0.0.0 --port 8001
```

The workflows automatically use this service for:
- Mobile application analysis
- Web application vulnerability scanning
- Code security analysis
- Integration with professional tools

## 🚨 Security Considerations

### Ethical Usage
- Only test systems you own or have explicit permission to test
- Respect bug bounty program scope and rules
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Rate Limiting
- Workflows include built-in rate limiting
- Adjust concurrency settings for your environment
- Monitor target systems for impact

### Data Protection
- Results may contain sensitive information
- Secure storage of collected data
- Proper cleanup of temporary files
- Follow data retention policies

## 🛠️ Troubleshooting

### Common Issues

**Import Errors**:
```bash
# Ensure all dependencies are installed
pip install -r requirements.txt

# Check Python path
export PYTHONPATH=/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/workflows:$PYTHONPATH
```

**Permission Errors**:
```bash
# Make scripts executable
chmod +x *.py

# Run with appropriate permissions for network tools
sudo python3 network-scanning.py  # May be needed for raw sockets
```

**Tool Not Found**:
```bash
# Check if required tools are installed
which nmap nuclei ffuf
```

### Performance Optimization

**Large Target Lists**:
- Use batch processing
- Adjust concurrency limits
- Monitor system resources

**Network Timeouts**:
- Increase timeout values in code
- Check network connectivity
- Use local DNS servers

## 📚 Documentation References

- **PLATFORM-SCANNING-GUIDE.md**: Complete platform overview
- **HACKTRICKS-ATTACK-VECTOR-MAPPING.md**: Detailed attack vector mapping
- **HackTricks Wiki**: https://book.hacktricks.wiki/en/index.html
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

## 🤝 Contributing

To extend the workflows:

1. Follow the existing code structure
2. Add comprehensive error handling
3. Include progress logging
4. Update documentation
5. Add tests where appropriate

## 📞 Support

For issues or questions:
- Check troubleshooting section
- Review log outputs with `--verbose`
- Ensure all dependencies are installed
- Verify target accessibility

---

**QuantumSentinel-Nexus**: Complete HackTricks methodology implementation for professional security testing.