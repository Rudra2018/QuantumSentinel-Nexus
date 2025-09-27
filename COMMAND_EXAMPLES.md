# 🚀 QuantumSentinel-Nexus Command Examples

## 📱 Local Command Interface

### Interactive Mode (Recommended for First Use)
```bash
python3 quantum_commander.py interactive
```
*Guided setup with prompts for scan type, targets, platforms, and execution environment*

---

## 🎯 Direct Command Examples

### Mobile Application Security
```bash
# Comprehensive mobile scan for HackerOne programs
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab,dropbox

# Quick mobile assessment
python3 quantum_commander.py scan mobile --targets shopify,uber --depth quick

# Mobile scan with cloud execution
python3 quantum_commander.py scan mobile --targets all --cloud
```

### Multi-Platform Bug Bounty Testing
```bash
# Test across all major platforms
python3 quantum_commander.py scan multi-platform \
  --platforms hackerone,bugcrowd,google_vrp,microsoft_msrc \
  --targets example.com,api.example.com

# Focus on high-bounty platforms
python3 quantum_commander.py scan multi-platform \
  --platforms google_vrp,microsoft_msrc,apple_security \
  --targets target.com --cloud

# European platforms focus
python3 quantum_commander.py scan multi-platform \
  --platforms intigriti,hackerone \
  --targets eu-company.com
```

### Chaos ProjectDiscovery Integration
```bash
# Discover domains for major programs
python3 quantum_commander.py scan chaos --targets shopify,tesla,google,microsoft

# Full chaos discovery with cloud processing
python3 quantum_commander.py scan chaos --targets all --cloud

# Target-specific discovery
python3 quantum_commander.py scan chaos --targets uber,lyft,tesla
```

### Web Application Security
```bash
# Standard web app scan
python3 quantum_commander.py scan web --targets https://example.com,https://api.example.com

# Deep web application assessment
python3 quantum_commander.py scan web --targets https://target.com --depth comprehensive

# Cloud-powered web scan
python3 quantum_commander.py scan web --targets https://target.com --cloud
```

### Comprehensive Security Assessment
```bash
# Full comprehensive scan (mobile + web + chaos + multi-platform)
python3 quantum_commander.py scan comprehensive --targets example.com

# Comprehensive scan with cloud execution
python3 quantum_commander.py scan comprehensive --targets target.com --cloud --timeout 240

# Hybrid execution (local + cloud)
python3 quantum_commander.py scan comprehensive --targets example.com --timeout 180
```

---

## ☁️ Cloud API Examples

Once deployed to Google Cloud, trigger scans via HTTP API:

### Mobile Comprehensive Scan
```bash
curl -X POST https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "mobile_comprehensive",
    "targets": ["shopify", "uber", "gitlab", "dropbox", "slack"]
  }'
```

### Multi-Platform Assessment
```bash
curl -X POST https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "multi_platform",
    "platforms": ["hackerone", "bugcrowd", "google_vrp", "microsoft_msrc"],
    "targets": ["example.com", "api.example.com"]
  }'
```

### Chaos Discovery
```bash
curl -X POST https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "chaos_discovery",
    "targets": ["shopify", "tesla", "google", "microsoft", "apple"]
  }'
```

### Comprehensive Cloud Scan
```bash
curl -X POST https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "comprehensive",
    "targets": ["target.com"],
    "options": {
      "depth": "comprehensive",
      "max_duration_minutes": 240
    }
  }'
```

---

## 🎯 Specialized Use Cases

### HackerOne Mobile App Hunting
```bash
# Focus on highest-paying mobile programs
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab

# Quick reconnaissance
python3 quantum_commander.py scan mobile --targets shopify --depth quick

# Full mobile assessment with cloud power
python3 quantum_commander.py scan mobile --cloud --timeout 120
```

### Bug Bounty Platform Comparison
```bash
# Test same target across all platforms
python3 quantum_commander.py scan multi-platform \
  --platforms hackerone,bugcrowd,intigriti,google_vrp \
  --targets example.com

# Compare bounty potential
python3 quantum_commander.py scan multi-platform \
  --platforms all --targets target.com --cloud
```

### Target Discovery and Enumeration
```bash
# Discover subdomains and assets
python3 quantum_commander.py scan chaos --targets company-name

# Combine chaos discovery with multi-platform testing
python3 quantum_commander.py scan comprehensive --targets discovered-domains.txt
```

### Enterprise Assessment
```bash
# Full enterprise security assessment
python3 quantum_commander.py scan comprehensive \
  --targets enterprise.com,api.enterprise.com,mobile.enterprise.com \
  --cloud --timeout 300

# Focus on high-value enterprise platforms
python3 quantum_commander.py scan multi-platform \
  --platforms microsoft_msrc,google_vrp,apple_security \
  --targets enterprise.com
```

---

## 📊 Results Management

### View Local Results
```bash
# List all scan results
ls results/

# View latest scan summary
cat results/*/summary.md

# Check specific scan
cat results/cli_scan_1234567/scan_results.json
```

### Cloud Results Access
```bash
# List cloud scan results
gsutil ls gs://quantumsentinel-YOUR-PROJECT-results/scans/

# Download specific scan
gsutil cp -r gs://quantumsentinel-YOUR-PROJECT-results/scans/scan_123456/ ./

# View real-time logs
gcloud functions logs read quantum-scanner --region=us-central1 --follow
```

---

## 🔧 Configuration Management

### Initialize Configuration
```bash
python3 quantum_commander.py config init
```

### View Current Configuration
```bash
python3 quantum_commander.py config show
```

### Cloud Configuration
```bash
# Set up cloud integration
python3 quantum_commander.py config set --key cloud.enabled --value true
python3 quantum_commander.py config set --key cloud.project_id --value YOUR-PROJECT-ID
```

---

## 💡 Pro Tips

### Maximize Bug Bounty Success
1. **Start with mobile scans** - highest bounty potential
2. **Use chaos discovery** - find hidden attack surface
3. **Focus on vendor programs** - Google, Microsoft, Apple pay most
4. **Run comprehensive scans** - don't miss anything
5. **Use cloud for intensive tasks** - mobile app analysis, large target sets

### Cost Optimization
```bash
# Use quick scans for reconnaissance
--depth quick

# Local execution for development
# (no --cloud flag)

# Focused targeting
--targets specific-high-value-targets

# Time-limited scans
--timeout 60
```

### Advanced Workflows
```bash
# 1. Discovery phase
python3 quantum_commander.py scan chaos --targets company-list.txt

# 2. Target validation
python3 quantum_commander.py scan web --targets discovered-targets.txt --depth quick

# 3. Deep assessment
python3 quantum_commander.py scan comprehensive --targets validated-targets.txt --cloud

# 4. Platform-specific optimization
python3 quantum_commander.py scan multi-platform --platforms best-fit-platforms --targets final-targets.txt
```

---

## 🚨 Example Real-World Campaigns

### High-Value Mobile Campaign
```bash
# Phase 1: Mobile app discovery
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab,dropbox,slack,spotify,yahoo,twitter

# Phase 2: Deep analysis on promising targets
python3 quantum_commander.py scan mobile --targets shopify,uber --cloud --depth comprehensive

# Phase 3: Cross-platform validation
python3 quantum_commander.py scan multi-platform --platforms hackerone,bugcrowd --targets mobile-findings.txt
```

### Enterprise Penetration Test Simulation
```bash
# Full enterprise assessment
python3 quantum_commander.py scan comprehensive \
  --targets enterprise.com \
  --cloud \
  --timeout 300 \
  --depth comprehensive
```

### Bug Bounty Platform Optimization
```bash
# Test across all platforms to find best fit
python3 quantum_commander.py scan multi-platform \
  --platforms hackerone,bugcrowd,intigriti,google_vrp,microsoft_msrc,apple_security \
  --targets your-target.com \
  --cloud
```

---

**🎯 Ready to dominate bug bounty hunting with QuantumSentinel-Nexus!**

Start with the interactive mode to get familiar with the system:
```bash
python3 quantum_commander.py interactive
```