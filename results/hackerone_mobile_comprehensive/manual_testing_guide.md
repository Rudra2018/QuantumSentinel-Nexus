# 📱 HackerOne Mobile App Manual Testing Guide

## 🛠️ Required Tools

### Android Analysis:
- **APKTool**: `apt install apktool`
- **JADX**: Download from GitHub releases
- **MobSF**: `docker run -p 8000:8000 opensecurity/mobsf`
- **Frida**: `pip install frida-tools`
- **ADB**: Android Debug Bridge
- **Burp Suite**: Traffic interception

### iOS Analysis:
- **class-dump**: Binary analysis
- **otool**: Mach-O analysis
- **Hopper/IDA Pro**: Disassemblers
- **Frida**: Runtime manipulation
- **Proxyman/Charles**: Traffic interception

## 🔍 Testing Methodology

### 1. Static Analysis
```bash
# Extract APK
apktool d app.apk -o extracted/

# Decompile to Java
jadx -d decompiled/ app.apk

# Analyze manifest
aapt dump xmltree app.apk AndroidManifest.xml
```

### 2. Dynamic Analysis
```bash
# Install app
adb install app.apk

# Start Frida server
adb shell su -c 'frida-server &'

# Run Frida scripts
frida -U -f com.package.name -l ssl_bypass.js
```

## 🎯 High-Value Testing Areas

### Authentication Vulnerabilities:
- JWT token manipulation
- Biometric bypass techniques
- Session management flaws
- Multi-factor authentication bypass

### Data Storage Issues:
- Insecure local storage (SQLite, SharedPreferences)
- Keychain/Keystore vulnerabilities
- Backup data exposure
- Cache data leakage

### Network Security:
- SSL/TLS implementation flaws
- Certificate pinning bypass
- API parameter manipulation
- Man-in-the-middle attacks

### Business Logic:
- Payment processing vulnerabilities
- Privilege escalation
- Race conditions
- Input validation bypasses

## 💰 Bounty Potential by Program

| Program | Authentication | Payment Logic | Data Exposure | Business Logic |
|---------|----------------|---------------|---------------|----------------|
| **Shopify** | $2,000-$15,000 | $5,000-$25,000 | $1,000-$10,000 | $3,000-$20,000 |
| **Uber** | $1,500-$12,000 | $3,000-$20,000 | $800-$8,000 | $2,000-$15,000 |
| **GitLab** | $1,000-$8,000 | $2,000-$12,000 | $500-$5,000 | $1,500-$10,000 |
| **Dropbox** | $1,500-$10,000 | $2,000-$15,000 | $1,000-$8,000 | $2,000-$12,000 |

## 📋 Testing Checklist

### Pre-Testing:
- [ ] Download latest app versions
- [ ] Setup testing environment (rooted Android/jailbroken iOS)
- [ ] Configure proxy tools (Burp/ZAP)
- [ ] Install Frida and prepare scripts

### Static Analysis:
- [ ] Extract and analyze AndroidManifest.xml
- [ ] Review source code for hardcoded secrets
- [ ] Check for debug mode and backup flags
- [ ] Analyze network security configuration
- [ ] Review exported components and permissions

### Dynamic Analysis:
- [ ] Intercept and analyze API calls
- [ ] Test authentication mechanisms
- [ ] Bypass SSL pinning and root detection
- [ ] Analyze local data storage
- [ ] Test business logic flows

### Reporting:
- [ ] Document proof of concept
- [ ] Prepare impact assessment
- [ ] Include remediation recommendations
- [ ] Submit to appropriate HackerOne program

