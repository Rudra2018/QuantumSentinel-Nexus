# 🎯 QuantumSentinel-Nexus Dashboard Guide

## 🚀 **24/7 Persistent Dashboard**

Your security testing platform is now running 24/7 with instant access to comprehensive scanning capabilities.

### **🌟 Quick Start**

```bash
# Start persistent dashboard (runs 24/7)
./start-dashboard.sh

# Dashboard will be available at:
# 📊 Main Dashboard: http://localhost:8080
# 🔍 Bug Bounty Research: http://localhost:8002
```

### **✅ What's Fixed & Operational**

1. **🔧 Binary Analysis Service** - ✅ FIXED & RUNNING 24/7
2. **🎯 All AWS Services** - ✅ 10 microservices operational
3. **📱 Mobile Analysis** - ✅ APK/IPA comprehensive scanning
4. **🌐 Domain Scanning** - ✅ Full infrastructure analysis
5. **🎯 Bug Bounty Programs** - ✅ 30+ programs monitored
6. **📊 Web Dashboard** - ✅ Real-time monitoring & control

---

## 📱 **New Scan Types Available**

### **1. 📱 Android APK Analysis**
- **Upload**: Drag & drop APK files
- **Analysis**: Static + Dynamic + Security + ML
- **Features**: Permissions, components, reverse engineering, vulnerability detection
- **Output**: Comprehensive PDF reports with POCs

### **2. 📱 iOS IPA Analysis**
- **Upload**: Drag & drop IPA files
- **Analysis**: Info.plist, entitlements, frameworks, security analysis
- **Features**: iOS-specific vulnerability detection, binary analysis
- **Output**: Detailed security assessment reports

### **3. 🌐 Domain Security Scanning**
- **Target**: Any domain or URL
- **Analysis**: Infrastructure, web app security, fuzzing
- **Workflow**: Recon → Web Analysis → Fuzzing → ML Assessment
- **Output**: Complete domain security profile

### **4. 🎯 Bug Bounty Program Analysis**
- **Input**: Program name and URL
- **Analysis**: Scope research, target enumeration, vulnerability scanning
- **Workflow**: Research → Recon → Vulnerability Scanning → ML Prediction
- **Output**: Bug bounty program assessment

---

## 🎯 **Dashboard Features**

### **📊 Real-Time Monitoring**
- Live scan progress tracking
- Service health indicators
- Real-time vulnerability findings
- Interactive charts and metrics

### **📑 Comprehensive Reporting**
- PDF reports with POCs and screenshots
- Step-by-step reproduction instructions
- Executive summaries and technical details
- Downloadable and shareable reports

### **🔧 Advanced Controls**
- Multi-priority scanning (High/Medium/Low)
- Analysis depth selection (Basic/Comprehensive/Deep)
- Background task monitoring
- Service orchestration control

---

## 🛠️ **How to Use**

### **Starting the Dashboard**
```bash
# One-time setup (runs 24/7)
./start-dashboard.sh

# Check status
docker ps | grep quantumsentinel

# Access dashboard anytime
open http://localhost:8080
```

### **Scanning Workflow**

1. **📱 Mobile Apps**:
   - Click "📱 APK" or "📱 IPA" button
   - Upload your app file
   - Select analysis depth
   - Monitor progress in real-time

2. **🌐 Domains**:
   - Click "🌐 Domain" button
   - Enter domain/URL
   - Choose scan type
   - Track multi-stage analysis

3. **🎯 Bug Bounty Programs**:
   - Click "🎯 Program" button
   - Enter program details
   - Monitor comprehensive analysis
   - Download detailed reports

### **Managing Scans**
- **View All Scans**: Navigate to "Scans" tab
- **Monitor Progress**: Real-time progress bars and logs
- **Download Reports**: Click download button when complete
- **Scan History**: Full historical record maintained

---

## 🔧 **Service Architecture**

### **🎯 AWS Production Services** (Running 24/7)
```
✅ quantumsentinel-fuzzing (1/1 tasks)
✅ quantumsentinel-binary-analysis (1/1 tasks)
✅ quantumsentinel-reverse-engineering (1/1 tasks)
✅ quantumsentinel-ml-intelligence (1/1 tasks)
✅ quantumsentinel-reconnaissance (1/1 tasks)
✅ quantumsentinel-sast-dast (1/1 tasks)
✅ quantumsentinel-ibb-research (1/1 tasks)
✅ quantumsentinel-reporting (1/1 tasks)
✅ quantumsentinel-orchestration (1/1 tasks)
✅ quantumsentinel-web-ui (1/1 tasks)
```

### **🏠 Local Dashboard Services**
```
✅ Web UI Dashboard (Port 8080)
✅ IBB Research Service (Port 8002)
```

---

## 📋 **Workflow Orchestration**

### **6-Stage Security Analysis Pipeline**

1. **🔍 Reconnaissance** (Sequential)
   - Target enumeration and information gathering
   - Infrastructure mapping and discovery

2. **🔬 Analysis Phase** (Parallel)
   - **Binary Analysis**: Static and dynamic analysis
   - **Web Security**: SAST/DAST scanning
   - **Fuzzing**: Intelligent vulnerability discovery
   - **Reverse Engineering**: Deep binary research

3. **🧠 ML Intelligence** (Sequential)
   - Machine learning threat prediction
   - Vulnerability pattern analysis
   - Risk assessment and prioritization

### **Comprehensive Reporting**
- Real-time progress tracking
- Stage-by-stage result compilation
- PDF generation with all evidence
- Executive and technical summaries

---

## 🎯 **Key Benefits**

### **⚡ Always Available**
- 24/7 dashboard access
- No need to run scripts repeatedly
- Auto-restart on system reboot
- Persistent scan history

### **📱 Mobile-First Security**
- APK and IPA deep analysis
- Mobile-specific vulnerability detection
- Comprehensive app security assessment
- Real binary analysis capabilities

### **🌐 Enterprise-Grade Domain Scanning**
- Full infrastructure assessment
- Web application security testing
- Advanced fuzzing capabilities
- ML-powered threat detection

### **🎯 Bug Bounty Integration**
- Automated program research
- Scope analysis and target enumeration
- Comprehensive vulnerability scanning
- Detailed assessment reports

---

## 🔧 **Troubleshooting**

### **Dashboard Not Accessible**
```bash
# Check if services are running
docker ps | grep quantumsentinel

# Restart if needed
./start-dashboard.sh

# Check logs
docker logs quantumsentinel-nexus-web-ui-persistent
```

### **AWS Services Issues**
```bash
# Check AWS service status
aws ecs describe-services --cluster quantumsentinel-nexus-cluster --services quantumsentinel-binary-analysis

# All services should show: runningCount = 1, desiredCount = 1
```

### **File Upload Issues**
- Ensure files are valid APK/IPA format
- Check file size limits (recommended < 100MB)
- Verify dashboard has sufficient disk space

---

## 📞 **Support & Resources**

- **📊 Dashboard**: http://localhost:8080
- **🔍 Research**: http://localhost:8002
- **🎯 AWS Console**: https://console.aws.amazon.com/ecs/
- **📋 All Services**: Running on ECS cluster `quantumsentinel-nexus-cluster`

---

## 🎉 **You're All Set!**

Your QuantumSentinel-Nexus platform is now fully operational with:

✅ **24/7 Dashboard Access**
✅ **Mobile App Security Testing**
✅ **Domain & Infrastructure Scanning**
✅ **Bug Bounty Program Analysis**
✅ **Real-time Monitoring & Reporting**
✅ **AWS-Powered Microservices**

**🚀 Start scanning immediately at: http://localhost:8080**