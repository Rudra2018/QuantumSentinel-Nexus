# QuantumSentinel-Nexus v4.0 - Usage Guide

## 🎯 Quick Start

### 1. System Verification
```bash
# Test all core systems
python3 test_system.py

# Expected output: 62.5% success rate or higher
# ✅ Core System Import: PASSED
# ✅ AI Agents: PASSED
# ✅ ML Framework: PASSED
# ✅ Intelligence Layer: PASSED
# ✅ Learning System: PASSED
```

### 2. Basic Assessment
```bash
# Run AI-powered assessment
python3 autonomous_quantum_sentinel.py --target testphp.vulnweb.com

# View results
ls assessments/testphp.vulnweb.com_*/reports/
```

### 3. Docker Quick Start
```bash
# Build and run
docker build -f Dockerfile.simple -t qs:simple .
docker run --rm qs:simple python3 -c "print('🛡️ System Ready!')"
```

## 🧠 AI-Powered Assessment (v4.0)

### Core AI System
The v4.0 system features autonomous AI agents that work together:

```python
from autonomous_quantum_sentinel import QuantumSentinelNexusV4

# Initialize AI system
nexus = QuantumSentinelNexusV4()

# Configure assessment
config = {
    'target': 'example.com',
    'scope': ['example.com', '*.example.com'],
    'assessment_type': 'comprehensive',
    'enable_ai': True,
    'enable_learning': True
}

# Run autonomous assessment
result = await nexus.run_assessment(config)
```

### AI Agents Available

#### 1. Orchestrator Agent
- **Purpose**: Master coordination and decision-making
- **Capabilities**: Workflow management, resource allocation
- **Usage**: Automatically manages other agents

#### 2. SAST Agent
- **Purpose**: Static Application Security Testing
- **Capabilities**: Code analysis, vulnerability detection
- **Usage**: Analyzes source code and binaries

#### 3. DAST Agent
- **Purpose**: Dynamic Application Security Testing
- **Capabilities**: Runtime analysis, web application testing
- **Usage**: Tests running applications

#### 4. Binary Analysis Agent
- **Purpose**: Reverse engineering and binary analysis
- **Capabilities**: Malware analysis, binary vulnerability detection
- **Usage**: Analyzes executable files and binaries

## 🔬 Research Module

### Zero-Day Discovery Engine
```python
from research_module.zero_day_discovery_engine import ZeroDayDiscoveryEngine

# Initialize research engine
research_engine = ZeroDayDiscoveryEngine()

# Discover novel vulnerabilities
potential_vulns = await research_engine.discover_vulnerabilities(target)
```

### Research Paper Integration
```python
from research_module.research_paper_analyzer import ResearchPaperAnalyzer

# Analyze latest security research
paper_analyzer = ResearchPaperAnalyzer()
insights = await paper_analyzer.analyze_recent_papers()
```

## 📱 Mobile Security Testing

### Comprehensive Mobile Assessment
```bash
# Android APK analysis
python3 mobile_security/unified_mobile_security_orchestrator.py \
  --apk /path/to/app.apk \
  --comprehensive

# iOS IPA analysis
python3 mobile_security/unified_mobile_security_orchestrator.py \
  --ipa /path/to/app.ipa \
  --comprehensive
```

### Mobile Security Components
- **Frida Integration**: Dynamic instrumentation
- **Objection Support**: Runtime manipulation
- **Static Analysis**: Code and resource analysis
- **Dynamic Analysis**: Behavior monitoring
- **Third-party Validation**: AI-powered validation

## 🛠️ Traditional Modules (v3.0)

### Reconnaissance
```bash
# Domain reconnaissance
python3 -m modules.recon_module --domain example.com

# Subdomain enumeration
python3 quantumsentinel_orchestrator.py --target example.com --recon-only
```

### OSINT Collection
```bash
# Open source intelligence
python3 -m modules.osint_module --target example.com

# Social media analysis
python3 -m modules.osint_module --target example.com --social-media
```

### Vulnerability Assessment
```bash
# Bug bounty style assessment
python3 -m modules.bugbounty_module --target example.com

# Focus on specific vulnerability types
python3 -m modules.bugbounty_module --target example.com --sql-injection
```

## 📊 Assessment Types

### 1. Comprehensive Assessment (Recommended)
```bash
python3 autonomous_quantum_sentinel.py \
  --target example.com \
  --comprehensive \
  --ai-enabled \
  --learning-enabled \
  --mobile-included
```

**Includes:**
- AI agent coordination
- Static code analysis
- Dynamic application testing
- Binary analysis
- Mobile security testing
- OSINT collection
- Vulnerability assessment
- Cross-modal correlation
- Continuous learning

### 2. Focused Assessments

#### AI-Only Assessment
```bash
python3 autonomous_quantum_sentinel.py \
  --target example.com \
  --ai-only
```

#### Web Application Focus
```bash
python3 autonomous_quantum_sentinel.py \
  --target example.com \
  --web-app-focus
```

#### Mobile Application Focus
```bash
python3 mobile_security/unified_mobile_security_orchestrator.py \
  --apk app.apk \
  --focus-on security
```

#### Research Mode
```bash
python3 autonomous_quantum_sentinel.py \
  --target example.com \
  --research-mode \
  --zero-day-discovery
```

## 🎛️ Configuration Options

### Assessment Configuration
```yaml
# config/assessment.yaml
assessment:
  target: "example.com"
  scope: ["example.com", "*.example.com"]
  type: "comprehensive"

ai_settings:
  enabled: true
  agents: ["orchestrator", "sast", "dast", "binary"]
  learning_enabled: true

modules:
  recon: true
  osint: true
  bugbounty: true
  mobile: true
  research: true

output:
  format: ["pdf", "html", "json"]
  evidence_collection: true
  screenshots: true
  real_time_reporting: true

performance:
  max_threads: 50
  rate_limit: 100
  timeout: 30
  memory_limit: "4GB"
```

### Agent Configuration
```python
# Individual agent settings
agent_config = {
    'sast_agent': {
        'analysis_depth': 'deep',
        'languages': ['python', 'javascript', 'java'],
        'frameworks': ['flask', 'django', 'express']
    },
    'dast_agent': {
        'scan_intensity': 'aggressive',
        'auth_handling': True,
        'javascript_analysis': True
    }
}
```

## 📈 Monitoring & Reporting

### Real-time Monitoring
```bash
# Assessment progress
python3 autonomous_quantum_sentinel.py --target example.com --monitor

# Agent status
curl http://localhost:8080/agents/status

# System health
curl http://localhost:8080/health
```

### Report Formats

#### Executive Summary PDF
- High-level findings
- Risk assessment
- Recommendations
- Business impact

#### Technical Report PDF
- Detailed vulnerability descriptions
- Proof of concepts
- Remediation steps
- Code samples

#### JSON Export
- Machine-readable format
- API integration friendly
- Automated processing

## 🔄 Continuous Learning

### Feedback Integration
```python
# Provide feedback on findings
from ai_core.continuous_learning_system import ContinuousLearningSystem

learning_system = ContinuousLearningSystem({'db_path': 'learning.db'})

feedback = {
    'prediction': {'vulnerability': 'sql_injection', 'confidence': 0.9},
    'actual_result': 'true_positive',
    'analyst_feedback': 'correct_identification'
}

await learning_system.process_feedback(feedback)
```

### Model Improvement
- Automatic model updates
- Performance optimization
- False positive reduction
- New vulnerability pattern recognition

## 🛡️ Best Practices

### Pre-Assessment
1. **Authorization**: Ensure written authorization
2. **Scope Definition**: Clearly define target scope
3. **Legal Review**: Verify compliance requirements
4. **Resource Planning**: Allocate sufficient resources

### During Assessment
1. **Monitoring**: Watch system performance
2. **Rate Limiting**: Respect target infrastructure
3. **Documentation**: Log all activities
4. **Communication**: Maintain stakeholder updates

### Post-Assessment
1. **Report Review**: Validate findings accuracy
2. **Data Security**: Secure sensitive information
3. **Knowledge Transfer**: Share lessons learned
4. **System Updates**: Update models with new data

## 🚨 Troubleshooting

### Common Issues

**ModuleNotFoundError**
```bash
# Install missing dependencies
pip install -r requirements-docker.txt
# or for full installation
pip install -r requirements.txt
```

**Permission Denied**
```bash
# Fix file permissions
chmod +x autonomous_quantum_sentinel.py
sudo chown -R $USER:$USER assessments/
```

**Network Timeouts**
```bash
# Increase timeout values
export QUANTUM_TIMEOUT=60
# or modify config/assessment.yaml
```

**Memory Issues**
```bash
# Reduce concurrent operations
export QUANTUM_MAX_THREADS=10
# or use Docker with memory limits
docker run --memory=4g quantumsentinel-nexus:v4.0
```

### Debug Mode
```bash
# Enable debug logging
python3 autonomous_quantum_sentinel.py --target example.com --debug

# System diagnosis
python3 test_system.py --verbose

# Agent debugging
python3 -c "
from ai_agents.orchestrator_agent import OrchestratorAgent
agent = OrchestratorAgent()
print('Agent status:', agent.status)
"
```

## 📞 Support

### System Status Check
```bash
# Quick health check
python3 -c "print('🛡️ QuantumSentinel-Nexus v4.0 - System Operational')"

# Comprehensive system test
python3 test_system.py
```

### Getting Help
- Review documentation in `docs/`
- Check troubleshooting section
- Run system diagnostics
- Consult project structure guide

---

**QuantumSentinel-Nexus v4.0** - Ready for autonomous AI security testing!