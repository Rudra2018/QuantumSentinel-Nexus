# 🚀 QuantumSentinel-Nexus Deployment Guide

This guide covers deployment options and current status for the QuantumSentinel-Nexus platform.

## 📋 Current Deployment Status

**Account:** `rbcag789@gmail.com`
**Project:** `quantum-nexus-0927`
**Status:** ✅ Fully Operational

### Cloud Infrastructure
- **Cloud Function:** https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner
- **Storage Bucket:** `gs://quantum-nexus-storage-1758985575`
- **Web UI:** http://localhost:8080

## 🎯 Quick Start

### 1. Start Web Interface
```bash
cd web_ui
./start_ui.sh
# Access at: http://localhost:8080
```

### 2. Run Mobile Security Scan
```bash
python3 quantum_commander.py scan mobile --targets shopify,uber --depth comprehensive
```

### 3. Test Cloud Function
```bash
curl https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner
```

## 📖 Related Documentation

- [NEW_DEPLOYMENT_STATUS.md](../NEW_DEPLOYMENT_STATUS.md) - Latest deployment details
- [Web UI README](../web_ui/README.md) - Web interface documentation
- [SCAN_EXECUTION_RESULTS.md](../SCAN_EXECUTION_RESULTS.md) - Scan results and analysis