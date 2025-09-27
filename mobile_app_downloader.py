#!/usr/bin/env python3
"""
Mobile App Downloader and Analysis Automation
Downloads APKs/IPAs and performs automated security analysis
"""

import subprocess
import os
import requests
from pathlib import Path
import json

class MobileAppDownloader:
    def __init__(self):
        self.download_dir = Path("downloads/mobile_apps")
        self.download_dir.mkdir(parents=True, exist_ok=True)

    def download_apk_from_apkpure(self, package_name: str):
        """Download APK from APKPure website"""
        print(f"🔍 Attempting to download {package_name} from APKPure...")

        try:
            # APKPure download URL pattern
            apkpure_url = f"https://apkpure.com/{package_name.replace('.', '-')}/{package_name}"
            print(f"   Checking: {apkpure_url}")

            # This would require web scraping or APKPure API
            # For now, we'll provide instructions
            download_guide = self.download_dir / f"{package_name}_download_guide.txt"

            with open(download_guide, 'w') as f:
                f.write(f"APK Download Guide for {package_name}\n")
                f.write("=" * 50 + "\n\n")
                f.write("Automated Download Methods:\n")
                f.write(f"1. APKPure: {apkpure_url}\n")
                f.write(f"2. APKMirror: https://www.apkmirror.com/apk/{package_name}/\n")
                f.write(f"3. Play Store (with tools):\n")
                f.write(f"   - gplaycli -d {package_name}\n")
                f.write(f"   - apkeep -a {package_name}\n\n")
                f.write("Manual Download Steps:\n")
                f.write("1. Visit APKPure or APKMirror\n")
                f.write(f"2. Search for: {package_name}\n")
                f.write("3. Download latest version\n")
                f.write(f"4. Save to: {self.download_dir}\n")
                f.write(f"5. Rename to: {package_name}.apk\n\n")
                f.write("Security Analysis Commands:\n")
                f.write(f"   aapt dump badging {package_name}.apk\n")
                f.write(f"   apktool d {package_name}.apk\n")
                f.write(f"   jadx -d output {package_name}.apk\n")

            print(f"✅ Download guide created: {download_guide}")
            return str(download_guide)

        except Exception as e:
            print(f"❌ Error creating download guide: {str(e)}")
            return None

    def generate_frida_scripts(self, package_name: str):
        """Generate Frida scripts for runtime analysis"""
        scripts_dir = self.download_dir / f"{package_name}_frida_scripts"
        scripts_dir.mkdir(exist_ok=True)

        # Basic bypass script
        bypass_script = scripts_dir / "ssl_bypass.js"
        with open(bypass_script, 'w') as f:
            f.write("""
// SSL Pinning Bypass Script for """ + package_name + """
Java.perform(function() {
    console.log("[*] Starting SSL Bypass for """ + package_name + """");

    // OkHTTP3 bypass
    try {
        var okhttp3_CertificatePinner = Java.use("okhttp3.CertificatePinner");
        okhttp3_CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHTTP3 Certificate Pinning bypassed for: " + hostname);
        };
    } catch(err) {
        console.log("[!] OkHTTP3 not found");
    }

    // TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        X509TrustManager.checkClientTrusted.implementation = function(chain, authType) {
            console.log("[+] SSL Client Trust bypass");
        };

        X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] SSL Server Trust bypass");
        };
    } catch(err) {
        console.log("[!] TrustManager bypass failed");
    }
});
""")

        # Root detection bypass
        root_bypass_script = scripts_dir / "root_bypass.js"
        with open(root_bypass_script, 'w') as f:
            f.write("""
// Root Detection Bypass for """ + package_name + """
Java.perform(function() {
    console.log("[*] Starting Root Detection Bypass");

    // Common root detection methods
    var rootChecks = [
        "isDeviceRooted",
        "isRooted",
        "checkRoot",
        "detectRoot",
        "isJailbroken"
    ];

    Java.enumerateLoadedClasses({
        "onMatch": function(className) {
            if (className.toLowerCase().indexOf("root") !== -1 ||
                className.toLowerCase().indexOf("security") !== -1) {
                try {
                    var clazz = Java.use(className);
                    var methods = clazz.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        var methodName = method.getName();
                        if (rootChecks.some(check => methodName.toLowerCase().includes(check.toLowerCase()))) {
                            console.log("[+] Hooking: " + className + "." + methodName);
                            clazz[methodName].implementation = function() {
                                console.log("[+] Root check bypassed: " + methodName);
                                return false;
                            };
                        }
                    });
                } catch(err) {
                    // Ignore errors
                }
            }
        },
        "onComplete": function() {}
    });
});
""")

        # API monitoring script
        api_monitor_script = scripts_dir / "api_monitor.js"
        with open(api_monitor_script, 'w') as f:
            f.write("""
// API Monitoring for """ + package_name + """
Java.perform(function() {
    console.log("[*] Starting API Monitoring");

    // HTTP URL Connection monitoring
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var connection = this.openConnection();
            console.log("[+] HTTP Connection: " + this.toString());
            return connection;
        };
    } catch(err) {
        console.log("[!] URL monitoring failed");
    }

    // OkHTTP monitoring
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");

        OkHttpClient.newCall.implementation = function(request) {
            console.log("[+] OkHTTP Request: " + request.url().toString());
            console.log("[+] Method: " + request.method());
            console.log("[+] Headers: " + request.headers().toString());
            return this.newCall(request);
        };
    } catch(err) {
        console.log("[!] OkHTTP monitoring failed");
    }
});
""")

        print(f"✅ Frida scripts generated in: {scripts_dir}")
        return str(scripts_dir)

def create_manual_testing_guide():
    """Create comprehensive manual testing guide"""
    guide_path = Path("results/hackerone_mobile_comprehensive/manual_testing_guide.md")
    guide_path.parent.mkdir(parents=True, exist_ok=True)

    with open(guide_path, 'w') as f:
        f.write("# 📱 HackerOne Mobile App Manual Testing Guide\n\n")
        f.write("## 🛠️ Required Tools\n\n")
        f.write("### Android Analysis:\n")
        f.write("- **APKTool**: `apt install apktool`\n")
        f.write("- **JADX**: Download from GitHub releases\n")
        f.write("- **MobSF**: `docker run -p 8000:8000 opensecurity/mobsf`\n")
        f.write("- **Frida**: `pip install frida-tools`\n")
        f.write("- **ADB**: Android Debug Bridge\n")
        f.write("- **Burp Suite**: Traffic interception\n\n")

        f.write("### iOS Analysis:\n")
        f.write("- **class-dump**: Binary analysis\n")
        f.write("- **otool**: Mach-O analysis\n")
        f.write("- **Hopper/IDA Pro**: Disassemblers\n")
        f.write("- **Frida**: Runtime manipulation\n")
        f.write("- **Proxyman/Charles**: Traffic interception\n\n")

        f.write("## 🔍 Testing Methodology\n\n")
        f.write("### 1. Static Analysis\n")
        f.write("```bash\n")
        f.write("# Extract APK\n")
        f.write("apktool d app.apk -o extracted/\n\n")
        f.write("# Decompile to Java\n")
        f.write("jadx -d decompiled/ app.apk\n\n")
        f.write("# Analyze manifest\n")
        f.write("aapt dump xmltree app.apk AndroidManifest.xml\n")
        f.write("```\n\n")

        f.write("### 2. Dynamic Analysis\n")
        f.write("```bash\n")
        f.write("# Install app\n")
        f.write("adb install app.apk\n\n")
        f.write("# Start Frida server\n")
        f.write("adb shell su -c 'frida-server &'\n\n")
        f.write("# Run Frida scripts\n")
        f.write("frida -U -f com.package.name -l ssl_bypass.js\n")
        f.write("```\n\n")

        f.write("## 🎯 High-Value Testing Areas\n\n")
        f.write("### Authentication Vulnerabilities:\n")
        f.write("- JWT token manipulation\n")
        f.write("- Biometric bypass techniques\n")
        f.write("- Session management flaws\n")
        f.write("- Multi-factor authentication bypass\n\n")

        f.write("### Data Storage Issues:\n")
        f.write("- Insecure local storage (SQLite, SharedPreferences)\n")
        f.write("- Keychain/Keystore vulnerabilities\n")
        f.write("- Backup data exposure\n")
        f.write("- Cache data leakage\n\n")

        f.write("### Network Security:\n")
        f.write("- SSL/TLS implementation flaws\n")
        f.write("- Certificate pinning bypass\n")
        f.write("- API parameter manipulation\n")
        f.write("- Man-in-the-middle attacks\n\n")

        f.write("### Business Logic:\n")
        f.write("- Payment processing vulnerabilities\n")
        f.write("- Privilege escalation\n")
        f.write("- Race conditions\n")
        f.write("- Input validation bypasses\n\n")

        f.write("## 💰 Bounty Potential by Program\n\n")
        f.write("| Program | Authentication | Payment Logic | Data Exposure | Business Logic |\n")
        f.write("|---------|----------------|---------------|---------------|----------------|\n")
        f.write("| **Shopify** | $2,000-$15,000 | $5,000-$25,000 | $1,000-$10,000 | $3,000-$20,000 |\n")
        f.write("| **Uber** | $1,500-$12,000 | $3,000-$20,000 | $800-$8,000 | $2,000-$15,000 |\n")
        f.write("| **GitLab** | $1,000-$8,000 | $2,000-$12,000 | $500-$5,000 | $1,500-$10,000 |\n")
        f.write("| **Dropbox** | $1,500-$10,000 | $2,000-$15,000 | $1,000-$8,000 | $2,000-$12,000 |\n\n")

        f.write("## 📋 Testing Checklist\n\n")
        f.write("### Pre-Testing:\n")
        f.write("- [ ] Download latest app versions\n")
        f.write("- [ ] Setup testing environment (rooted Android/jailbroken iOS)\n")
        f.write("- [ ] Configure proxy tools (Burp/ZAP)\n")
        f.write("- [ ] Install Frida and prepare scripts\n\n")

        f.write("### Static Analysis:\n")
        f.write("- [ ] Extract and analyze AndroidManifest.xml\n")
        f.write("- [ ] Review source code for hardcoded secrets\n")
        f.write("- [ ] Check for debug mode and backup flags\n")
        f.write("- [ ] Analyze network security configuration\n")
        f.write("- [ ] Review exported components and permissions\n\n")

        f.write("### Dynamic Analysis:\n")
        f.write("- [ ] Intercept and analyze API calls\n")
        f.write("- [ ] Test authentication mechanisms\n")
        f.write("- [ ] Bypass SSL pinning and root detection\n")
        f.write("- [ ] Analyze local data storage\n")
        f.write("- [ ] Test business logic flows\n\n")

        f.write("### Reporting:\n")
        f.write("- [ ] Document proof of concept\n")
        f.write("- [ ] Prepare impact assessment\n")
        f.write("- [ ] Include remediation recommendations\n")
        f.write("- [ ] Submit to appropriate HackerOne program\n\n")

    print(f"✅ Manual testing guide created: {guide_path}")
    return str(guide_path)

def main():
    """Main function"""
    print("📱 Mobile App Downloader & Analysis Setup")
    print("=" * 50)

    downloader = MobileAppDownloader()

    # High-priority apps to download
    priority_apps = [
        "com.shopify.mobile",
        "com.ubercab",
        "com.gitlab.gitlab",
        "com.dropbox.android",
        "com.twitter.android"
    ]

    for package_name in priority_apps:
        print(f"\n🎯 Processing: {package_name}")

        # Create download guide
        downloader.download_apk_from_apkpure(package_name)

        # Generate Frida scripts
        downloader.generate_frida_scripts(package_name)

    # Create comprehensive testing guide
    create_manual_testing_guide()

    print("\n✅ Mobile app testing setup completed!")
    print("\nNext steps:")
    print("1. Download APKs using the generated guides")
    print("2. Setup testing environment (rooted device/emulator)")
    print("3. Use Frida scripts for runtime analysis")
    print("4. Follow manual testing guide for comprehensive assessment")

if __name__ == "__main__":
    main()