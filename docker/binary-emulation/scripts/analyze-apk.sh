#!/bin/bash
# QuantumSentinel APK Analysis Script
# Comprehensive analysis of Android APK files

set -euo pipefail

APK_PATH="$1"
OUTPUT_DIR="/analysis/results/$(basename "$APK_PATH")_apk_analysis_$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if APK exists
if [ ! -f "$APK_PATH" ]; then
    error "APK file not found: $APK_PATH"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

log "Starting APK analysis for: $(basename "$APK_PATH")"
log "Output directory: $OUTPUT_DIR"

# Basic file information
log "=== Basic File Information ==="
file "$APK_PATH" > file_info.txt
ls -la "$APK_PATH" > file_stats.txt
unzip -l "$APK_PATH" > apk_contents.txt 2>/dev/null || warn "Failed to list APK contents"

# Extract APK contents
log "=== APK Extraction ==="
mkdir -p extracted
cd extracted
unzip -q "$APK_PATH" 2>/dev/null || warn "APK extraction had issues"
cd ..

# APK metadata analysis
log "=== APK Metadata Analysis ==="
if command -v aapt >/dev/null 2>&1; then
    aapt dump badging "$APK_PATH" > apk_metadata.txt 2>/dev/null || warn "aapt analysis failed"
    aapt dump permissions "$APK_PATH" > apk_permissions.txt 2>/dev/null || warn "aapt permissions failed"
    aapt dump configurations "$APK_PATH" > apk_configurations.txt 2>/dev/null || warn "aapt configurations failed"
else
    warn "aapt not available"
fi

# AndroidManifest.xml analysis
log "=== AndroidManifest.xml Analysis ==="
if [ -f "extracted/AndroidManifest.xml" ]; then
    # Try to parse binary XML
    if command -v aapt >/dev/null 2>&1; then
        aapt dump xmltree "$APK_PATH" AndroidManifest.xml > manifest_readable.xml 2>/dev/null || warn "aapt manifest parsing failed"
    fi

    # Use axmlparserpy for parsing
    python3 << EOF
try:
    from axmlparserpy.axmlparserpy import AXML
    import json

    with open("extracted/AndroidManifest.xml", "rb") as f:
        axml = AXML(f.read())

    manifest_data = {
        "package_name": None,
        "version_code": None,
        "version_name": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": []
    }

    # Extract key information
    xml_content = axml.get_xml()
    with open("manifest_parsed.xml", "w") as f:
        f.write(xml_content)

    # Parse for security-relevant information
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_content)

    # Package info
    manifest_data["package_name"] = root.get("package")

    # Find permissions
    for permission in root.findall(".//uses-permission"):
        perm_name = permission.get("{http://schemas.android.com/apk/res/android}name")
        if perm_name:
            manifest_data["permissions"].append(perm_name)

    # Find activities
    for activity in root.findall(".//activity"):
        activity_name = activity.get("{http://schemas.android.com/apk/res/android}name")
        if activity_name:
            manifest_data["activities"].append(activity_name)

    with open("manifest_analysis.json", "w") as f:
        json.dump(manifest_data, f, indent=2)

    print(f"✅ Manifest analysis completed - Found {len(manifest_data['permissions'])} permissions")

except Exception as e:
    print(f"❌ Manifest analysis failed: {e}")
EOF
fi

# APK decompilation with apktool
log "=== APK Decompilation ==="
if command -v apktool >/dev/null 2>&1; then
    mkdir -p decompiled
    apktool d "$APK_PATH" -o decompiled/ -f > apktool_output.txt 2>&1 || warn "apktool decompilation failed"
else
    warn "apktool not available"
fi

# DEX analysis
log "=== DEX Analysis ==="
if [ -f "extracted/classes.dex" ]; then
    # Basic DEX info
    hexdump -C extracted/classes.dex | head -10 > dex_header.txt

    # dex2jar conversion
    if command -v dex2jar >/dev/null 2>&1; then
        dex2jar extracted/classes.dex -o classes.jar > dex2jar_output.txt 2>&1 || warn "dex2jar failed"
    fi
fi

# JADX decompilation
log "=== Java Source Decompilation ==="
if command -v jadx >/dev/null 2>&1; then
    mkdir -p jadx_output
    jadx -d jadx_output "$APK_PATH" > jadx_log.txt 2>&1 || warn "JADX decompilation failed"
fi

# String analysis
log "=== String Analysis ==="
if [ -f "extracted/classes.dex" ]; then
    strings extracted/classes.dex | head -1000 > dex_strings.txt
fi

# Additional strings from resources
find extracted/ -name "*.xml" -o -name "*.txt" -o -name "*.json" | xargs strings 2>/dev/null | head -500 > resource_strings.txt || true

# Certificate analysis
log "=== Certificate Analysis ==="
if [ -d "extracted/META-INF" ]; then
    mkdir -p certificate_analysis

    # Copy certificate files
    cp extracted/META-INF/* certificate_analysis/ 2>/dev/null || true

    # Analyze certificates
    for cert_file in extracted/META-INF/*.RSA extracted/META-INF/*.DSA 2>/dev/null; do
        if [ -f "$cert_file" ]; then
            openssl pkcs7 -inform DER -in "$cert_file" -print_certs -text > "certificate_analysis/$(basename "$cert_file").txt" 2>/dev/null || warn "Certificate analysis failed for $cert_file"
        fi
    done
fi

# Security analysis with Androguard
log "=== Security Analysis with Androguard ==="
python3 << EOF
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    import json

    apk = APK("$APK_PATH")

    security_analysis = {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_code": apk.get_androidversion_code(),
        "version_name": apk.get_androidversion_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": apk.get_permissions(),
        "dangerous_permissions": [],
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
        "is_signed": apk.is_signed(),
        "is_debug": apk.is_debug(),
        "vulnerabilities": []
    }

    # Check for dangerous permissions
    dangerous_perms = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ]

    for perm in apk.get_permissions():
        if perm in dangerous_perms:
            security_analysis["dangerous_permissions"].append(perm)

    # Basic vulnerability checks
    if apk.is_debug():
        security_analysis["vulnerabilities"].append("Debug flag enabled")

    if not apk.is_signed():
        security_analysis["vulnerabilities"].append("APK is not signed")

    # Check for exported components
    for activity in apk.get_activities():
        if "android:exported" in str(activity):
            security_analysis["vulnerabilities"].append(f"Exported activity: {activity}")

    with open("androguard_analysis.json", "w") as f:
        json.dump(security_analysis, f, indent=2)

    print(f"✅ Androguard analysis completed")
    print(f"   Package: {security_analysis['package_name']}")
    print(f"   Permissions: {len(security_analysis['permissions'])}")
    print(f"   Dangerous permissions: {len(security_analysis['dangerous_permissions'])}")
    print(f"   Vulnerabilities: {len(security_analysis['vulnerabilities'])}")

except Exception as e:
    print(f"❌ Androguard analysis failed: {e}")
EOF

# Network security analysis
log "=== Network Security Analysis ==="
python3 << EOF
import re
import json

network_analysis = {
    "http_urls": [],
    "https_urls": [],
    "ip_addresses": [],
    "domains": [],
    "potential_c2": [],
    "insecure_protocols": []
}

try:
    # Search for URLs and IPs in all extracted content
    import os
    for root, dirs, files in os.walk("extracted/"):
        for file in files:
            if file.endswith(('.xml', '.txt', '.json', '.js')):
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()

                    # Find URLs
                    http_urls = re.findall(r'http://[^\s<>"]+', content)
                    https_urls = re.findall(r'https://[^\s<>"]+', content)

                    network_analysis["http_urls"].extend(http_urls)
                    network_analysis["https_urls"].extend(https_urls)

                    # Find IP addresses
                    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                    network_analysis["ip_addresses"].extend(ips)

                    # Check for insecure protocols
                    if 'http://' in content and 'password' in content.lower():
                        network_analysis["insecure_protocols"].append("HTTP with potential credentials")

                except Exception:
                    continue

    # Remove duplicates
    for key in network_analysis:
        if isinstance(network_analysis[key], list):
            network_analysis[key] = list(set(network_analysis[key]))

    with open("network_analysis.json", "w") as f:
        json.dump(network_analysis, f, indent=2)

    print(f"✅ Network analysis completed")
    print(f"   HTTP URLs: {len(network_analysis['http_urls'])}")
    print(f"   HTTPS URLs: {len(network_analysis['https_urls'])}")
    print(f"   IP addresses: {len(network_analysis['ip_addresses'])}")

except Exception as e:
    print(f"❌ Network analysis failed: {e}")
EOF

# Generate analysis summary
log "=== Generating Analysis Summary ==="
cat > analysis_summary.txt << EOL
QuantumSentinel APK Analysis Report
=================================
APK: $(basename "$APK_PATH")
Analysis Date: $(date)
Output Directory: $OUTPUT_DIR

Files Generated:
- file_info.txt: Basic file information
- apk_contents.txt: APK contents listing
- apk_metadata.txt: APK metadata (aapt)
- apk_permissions.txt: APK permissions
- manifest_analysis.json: AndroidManifest.xml analysis
- androguard_analysis.json: Androguard security analysis
- network_analysis.json: Network security analysis
- decompiled/: APKTool decompiled output
- jadx_output/: JADX decompiled Java source
- certificate_analysis/: Certificate information
- dex_strings.txt: Strings extracted from DEX
- resource_strings.txt: Strings from resources

Analysis completed successfully!
EOL

log "=== Analysis Complete ==="
log "Results saved to: $OUTPUT_DIR"

# Security risk assessment
log "=== Security Risk Assessment ==="
python3 << EOF
import json
import os

risk_score = 0
risk_factors = []

try:
    # Load analysis results
    if os.path.exists("androguard_analysis.json"):
        with open("androguard_analysis.json", "r") as f:
            androguard = json.load(f)

        # Risk factors
        if androguard.get("is_debug"):
            risk_score += 20
            risk_factors.append("Debug flag enabled (+20)")

        if not androguard.get("is_signed"):
            risk_score += 30
            risk_factors.append("APK not signed (+30)")

        dangerous_perms = len(androguard.get("dangerous_permissions", []))
        if dangerous_perms > 5:
            risk_score += 25
            risk_factors.append(f"Many dangerous permissions: {dangerous_perms} (+25)")
        elif dangerous_perms > 0:
            risk_score += 10
            risk_factors.append(f"Dangerous permissions: {dangerous_perms} (+10)")

        vulns = len(androguard.get("vulnerabilities", []))
        risk_score += vulns * 15
        if vulns > 0:
            risk_factors.append(f"Vulnerabilities found: {vulns} (+{vulns*15})")

    if os.path.exists("network_analysis.json"):
        with open("network_analysis.json", "r") as f:
            network = json.load(f)

        if len(network.get("http_urls", [])) > 0:
            risk_score += 15
            risk_factors.append(f"HTTP URLs found: {len(network['http_urls'])} (+15)")

        if len(network.get("insecure_protocols", [])) > 0:
            risk_score += 20
            risk_factors.append("Insecure protocols detected (+20)")

    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    risk_assessment = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "total_factors": len(risk_factors)
    }

    with open("risk_assessment.json", "w") as f:
        json.dump(risk_assessment, f, indent=2)

    print(f"Risk Assessment: {risk_level} (Score: {risk_score})")
    for factor in risk_factors:
        print(f"  - {factor}")

except Exception as e:
    print(f"❌ Risk assessment failed: {e}")
EOF

log "APK analysis complete! Check $OUTPUT_DIR for results."