# 🌐 QuantumSentinel-Nexus Web UI

A comprehensive web interface for the QuantumSentinel-Nexus bug bounty platform with integrated Claude AI assistance.

## ✨ Features

### 🎯 Core Capabilities
- **Multi-Platform Scanner** - Execute scans across 7 bug bounty platforms
- **Mobile Security Suite** - Comprehensive analysis of 42 mobile applications
- **Cloud Integration** - Seamless Google Cloud Function execution
- **Claude AI Assistant** - Intelligent vulnerability analysis and guidance
- **Real-time Monitoring** - Live scan progress and results tracking
- **Professional Reporting** - Export-ready vulnerability documentation

### 🚀 Interface Highlights

#### **Dashboard**
- System status monitoring
- Quick statistics overview
- Recent scan history
- One-click scan initiation
- Cloud resource monitoring

#### **Advanced Scanner**
- Intuitive scan configuration
- Real-time terminal output
- Pre-built scan templates
- Multi-target batch processing
- Cloud vs local execution options

#### **Mobile Security**
- 42 mobile apps across 8 HackerOne programs
- Program-specific bounty estimates
- Platform-specific analysis tools
- APK/IPA inspection utilities
- Dynamic testing frameworks

#### **Cloud Management**
- Google Cloud infrastructure monitoring
- Cost optimization controls
- Storage bucket browser
- Deployment management
- Performance metrics

#### **Claude AI Integration**
- Intelligent security advisor
- Context-aware vulnerability analysis
- Bug bounty strategy optimization
- Report writing assistance
- Best practices guidance

#### **Results Analytics**
- Comprehensive findings dashboard
- Severity-based prioritization
- Bounty potential estimation
- Export capabilities
- Progress tracking

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Google Cloud SDK (for cloud features)
- Active internet connection

### Installation

1. **Navigate to the web UI directory:**
   ```bash
   cd /Users/ankitthakur/Downloads/QuantumSentinel-Nexus/web_ui/
   ```

2. **Start the web interface:**
   ```bash
   ./start_ui.sh
   ```

3. **Access the interface:**
   Open your browser and go to: **http://localhost:8080**

### Manual Installation

If the startup script fails, you can install dependencies manually:

```bash
# Install Python dependencies
pip3 install flask flask-cors requests

# Start the server
python3 server.py
```

## 🎯 Usage Guide

### Starting a Scan

1. **Navigate to the Scanner tab**
2. **Configure your scan:**
   - Select scan type (Mobile, Multi-Platform, Comprehensive, Chaos)
   - Enter targets (comma-separated)
   - Choose platforms (HackerOne, Bugcrowd, etc.)
   - Set scan depth (Quick, Standard, Comprehensive, Deep)
   - Enable cloud execution if desired

3. **Click "Start Scan"**
4. **Monitor progress** in the terminal output

### Using Scan Templates

Quick-start with pre-configured templates:

- **HackerOne Mobile**: All 42 mobile apps across 8 programs
- **Multi-Platform Web**: Web applications across all platforms
- **Chaos Enterprise**: Large-scale domain discovery
- **AI-Assisted Analysis**: Claude-powered vulnerability detection

### Claude AI Assistant

1. **Navigate to the Claude AI tab**
2. **Start a conversation** with security-focused queries
3. **Use quick actions** for common requests:
   - Mobile Security Best Practices
   - Bug Bounty Tips
   - Vulnerability Prioritization
   - Report Templates

4. **Get contextual advice** based on your scan results

### Mobile Security Analysis

1. **Navigate to the Mobile tab**
2. **Browse available programs** (Shopify, Uber, Dropbox, etc.)
3. **Click "Scan Now"** for immediate analysis
4. **View detailed app breakdowns** with "View Apps"
5. **Access bounty estimates** and focus areas

### Cloud Integration

1. **Navigate to the Cloud tab**
2. **Monitor infrastructure status**
3. **Browse cloud storage** for results
4. **Manage deployment** and scaling
5. **Optimize costs** with built-in controls

## 🔧 Configuration

### API Keys

Configure API keys in the Settings tab:

- **Chaos ProjectDiscovery**: Already configured (`1545c524-7e20-4b62-aa4a-8235255cff96`)
- **Claude API Key**: Optional for enhanced AI features

### Cloud Settings

The interface auto-detects your cloud configuration:

- **Project ID**: `quantumsentinel-20250927`
- **Cloud Function**: `https://us-central1-quantumsentinel-20250927.cloudfunctions.net/quantum-scanner`
- **Storage Bucket**: `gs://quantumsentinel-nexus-1758983113-results`

### General Settings

Customize behavior in Settings:
- Default scan types and timeouts
- Notification preferences
- Auto-save and cloud sync options
- Concurrent scan limits

## 📊 Understanding Results

### Dashboard Metrics
- **Mobile Apps**: 42 applications analyzed
- **Programs**: 8 HackerOne programs covered
- **Platforms**: 7 bug bounty platforms supported
- **Bounty Potential**: Combined maximum potential

### Scan Results
- **Critical/High/Medium/Low** severity classification
- **Bounty estimates** based on platform and vulnerability type
- **Target information** and affected components
- **Actionable remediation** guidance

### Mobile Program Priorities

**High Priority (Start Here):**
- **Shopify**: $5,000-$50,000+ (8 apps)
- **Uber**: $1,000-$25,000+ (8 apps)
- **Dropbox**: $1,000-$15,000+ (6 apps)

**Medium Priority:**
- **Twitter**: $560-$15,000+ (4 apps)
- **GitLab**: $1,000-$10,000+ (2 apps)
- **Slack**: $500-$8,000+ (4 apps)
- **Spotify**: $250-$5,000+ (4 apps)
- **Yahoo**: $250-$5,000+ (6 apps)

## 🔗 Integration

### Local Command Integration

The web UI seamlessly integrates with your local QuantumSentinel commands:

```bash
# Web UI automatically translates to:
python3 quantum_commander.py scan mobile --targets shopify,uber --depth comprehensive
```

### Cloud Function Integration

Direct integration with your deployed cloud function:

```bash
# HTTP API calls to:
curl -X POST https://us-central1-quantumsentinel-20250927.cloudfunctions.net/quantum-scanner \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify", "uber"]}'
```

### Claude AI Integration

Built-in AI assistant for:
- **Vulnerability Analysis**: Intelligent threat assessment
- **Strategy Optimization**: Bug bounty targeting advice
- **Report Generation**: Professional documentation assistance
- **Best Practices**: Security testing guidance

## 🛠️ Troubleshooting

### Common Issues

**Port 8080 already in use:**
```bash
# Find and kill the process using port 8080
lsof -ti:8080 | xargs kill -9

# Or use a different port
python3 server.py --port 8081
```

**Cloud function unreachable:**
- Check internet connection
- Verify cloud function URL in settings
- Test with: `curl https://us-central1-quantumsentinel-20250927.cloudfunctions.net/quantum-scanner`

**Missing dependencies:**
```bash
pip3 install flask flask-cors requests
```

**Permission denied on startup script:**
```bash
chmod +x start_ui.sh
```

### Performance Optimization

- **Local Scans**: Faster execution, no network dependencies
- **Cloud Scans**: Scalable processing, results stored in cloud
- **Concurrent Limits**: Adjust in settings based on system resources
- **Browser**: Use Chrome/Edge for best performance

## 📚 Advanced Features

### Custom Scan Templates

Create custom templates by modifying the configuration in Settings or using the API:

```javascript
// Custom template via JavaScript console
QuantumSentinel.loadTemplate('custom-template');
```

### API Endpoints

The web UI exposes REST APIs for integration:

- `GET /api/status` - System status
- `POST /api/scan` - Start new scan
- `GET /api/scan/<id>/status` - Scan progress
- `GET /api/mobile-programs` - Mobile program data
- `POST /api/claude/chat` - Claude AI interaction

### Export Capabilities

- **Scan Results**: JSON, Markdown, PDF formats
- **Claude Conversations**: Text export for documentation
- **Configuration**: Settings backup/restore
- **Reports**: Professional vulnerability reports

## 🎯 Next Steps

1. **Start with high-value targets**: Focus on Shopify and Uber mobile apps
2. **Use Claude AI**: Get strategy advice and vulnerability guidance
3. **Monitor cloud resources**: Optimize costs and performance
4. **Export results**: Professional reporting for submissions
5. **Scale operations**: Leverage cloud capabilities for large assessments

## 💡 Pro Tips

- **Mobile Testing**: Start with Shopify apps for highest bounty potential
- **Multi-Platform**: Use for comprehensive target validation
- **Claude AI**: Ask specific questions about vulnerabilities and strategies
- **Cloud Execution**: Use for intensive scans and result persistence
- **Templates**: Save time with pre-configured common scenarios

---

**🎉 Your QuantumSentinel-Nexus Web UI is ready for professional bug bounty hunting!**

**Access at:** http://localhost:8080
**Documentation:** This README
**Support:** Claude AI assistant built-in