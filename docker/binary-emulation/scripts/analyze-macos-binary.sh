#!/bin/bash
# QuantumSentinel macOS Binary Analysis Script
# Comprehensive analysis of macOS binaries (Mach-O, .app, KEXT, dylib, framework)

set -euo pipefail

BINARY_PATH="$1"
OUTPUT_DIR="/analysis/results/$(basename "$BINARY_PATH")_analysis_$(date +%s)"
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

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    error "Binary file not found: $BINARY_PATH"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

log "Starting macOS binary analysis for: $(basename "$BINARY_PATH")"
log "Output directory: $OUTPUT_DIR"

# Basic file information
log "=== Basic File Information ==="
file "$BINARY_PATH" > file_info.txt
ls -la "$BINARY_PATH" > file_stats.txt

# Extract metadata using file command and otool
log "=== macOS Binary Metadata Extraction ==="
if command -v otool >/dev/null 2>&1; then
    otool -h "$BINARY_PATH" > mach_o_header.txt 2>/dev/null || warn "otool header extraction failed"
    otool -l "$BINARY_PATH" > mach_o_load_commands.txt 2>/dev/null || warn "otool load commands failed"
    otool -L "$BINARY_PATH" > mach_o_libraries.txt 2>/dev/null || warn "otool libraries failed"
else
    warn "otool not available, using alternative tools"
fi

# LIEF analysis
log "=== LIEF Binary Analysis ==="
python3 << EOF
import lief
import json

try:
    binary = lief.parse("$BINARY_PATH")
    if binary:
        metadata = {
            "format": str(binary.format),
            "architecture": str(binary.header.cpu_type) if hasattr(binary, 'header') else "unknown",
            "entry_point": hex(binary.entrypoint) if binary.entrypoint else "0x0",
            "sections": [{"name": s.name, "size": s.size} for s in binary.sections] if hasattr(binary, 'sections') else [],
            "libraries": [lib.name for lib in binary.libraries] if hasattr(binary, 'libraries') else [],
            "symbols": [sym.name for sym in binary.symbols][:50] if hasattr(binary, 'symbols') else []
        }

        with open("lief_analysis.json", "w") as f:
            json.dump(metadata, f, indent=2)

        print("✅ LIEF analysis completed")
    else:
        print("❌ LIEF failed to parse binary")

except Exception as e:
    print(f"❌ LIEF analysis failed: {e}")
EOF

# Radare2 analysis
log "=== Radare2 Analysis ==="
r2 -q -A -c "iI; iS; il; iz" "$BINARY_PATH" > radare2_analysis.txt 2>/dev/null || warn "Radare2 analysis failed"

# String extraction
log "=== String Extraction ==="
strings "$BINARY_PATH" | head -500 > strings.txt

# Code signing analysis
log "=== Code Signing Analysis ==="
if command -v codesign >/dev/null 2>&1; then
    codesign -vv -d "$BINARY_PATH" > code_signing.txt 2>&1 || warn "Code signing check failed"
else
    warn "codesign not available"
fi

# Security analysis
log "=== Security Analysis ==="
if command -v checksec >/dev/null 2>&1; then
    checksec --file="$BINARY_PATH" > security_features.txt 2>/dev/null || warn "checksec failed"
fi

# App bundle analysis (if it's an .app)
if [[ "$BINARY_PATH" == *.app ]] || [[ -d "$BINARY_PATH" ]]; then
    log "=== App Bundle Analysis ==="
    mkdir -p app_bundle_analysis

    # Extract Info.plist if it exists
    if [ -f "$BINARY_PATH/Contents/Info.plist" ]; then
        cp "$BINARY_PATH/Contents/Info.plist" app_bundle_analysis/

        # Convert binary plist to readable format
        if command -v plutil >/dev/null 2>&1; then
            plutil -p "$BINARY_PATH/Contents/Info.plist" > app_bundle_analysis/Info_readable.plist 2>/dev/null || true
        fi
    fi

    # List all files in the bundle
    find "$BINARY_PATH" -type f > app_bundle_analysis/bundle_files.txt 2>/dev/null || true
fi

# KEXT analysis (if it's a kernel extension)
if [[ "$BINARY_PATH" == *.kext ]] || [[ -d "$BINARY_PATH" && -f "$BINARY_PATH/Contents/Info.plist" ]]; then
    log "=== Kernel Extension Analysis ==="
    mkdir -p kext_analysis

    # Extract KEXT metadata
    if [ -f "$BINARY_PATH/Contents/Info.plist" ]; then
        cp "$BINARY_PATH/Contents/Info.plist" kext_analysis/

        # Look for OSBundleRequired and other KEXT-specific keys
        if command -v plutil >/dev/null 2>&1; then
            plutil -p "$BINARY_PATH/Contents/Info.plist" | grep -E "(OSBundle|IOKit)" > kext_analysis/kext_info.txt 2>/dev/null || true
        fi
    fi
fi

# Framework analysis (if it's a .framework)
if [[ "$BINARY_PATH" == *.framework ]] || [[ -d "$BINARY_PATH" ]]; then
    log "=== Framework Analysis ==="
    mkdir -p framework_analysis

    # Find the main binary in the framework
    if [ -d "$BINARY_PATH" ]; then
        find "$BINARY_PATH" -type f -perm +111 > framework_analysis/executables.txt 2>/dev/null || true
        find "$BINARY_PATH" -name "*.dylib" > framework_analysis/dylibs.txt 2>/dev/null || true
    fi
fi

# Generate analysis summary
log "=== Generating Analysis Summary ==="
cat > analysis_summary.txt << EOL
QuantumSentinel macOS Binary Analysis Report
==========================================
Binary: $(basename "$BINARY_PATH")
Analysis Date: $(date)
Output Directory: $OUTPUT_DIR

Files Generated:
- file_info.txt: Basic file information
- file_stats.txt: File statistics
- mach_o_header.txt: Mach-O header information
- mach_o_load_commands.txt: Load commands
- mach_o_libraries.txt: Linked libraries
- lief_analysis.json: LIEF binary analysis
- radare2_analysis.txt: Radare2 analysis
- strings.txt: Extracted strings
- code_signing.txt: Code signing information
- security_features.txt: Security features
$([ -d "app_bundle_analysis" ] && echo "- app_bundle_analysis/: App bundle analysis")
$([ -d "kext_analysis" ] && echo "- kext_analysis/: Kernel extension analysis")
$([ -d "framework_analysis" ] && echo "- framework_analysis/: Framework analysis")

Analysis completed successfully!
EOL

log "=== Analysis Complete ==="
log "Results saved to: $OUTPUT_DIR"
log "Summary: $(wc -l < analysis_summary.txt) lines generated"

# Check for common vulnerabilities
log "=== Security Assessment ==="
python3 << EOF
import re
import json

vulnerabilities = []

# Check strings for common issues
try:
    with open("strings.txt", "r") as f:
        strings_content = f.read()

    # Look for hardcoded credentials
    if re.search(r"password|admin|root|secret", strings_content, re.IGNORECASE):
        vulnerabilities.append("Potential hardcoded credentials found in strings")

    # Look for URLs
    urls = re.findall(r"https?://[^\s]+", strings_content)
    if urls:
        vulnerabilities.append(f"Found {len(urls)} URL(s) in binary")

    # Look for file paths
    paths = re.findall(r"/[a-zA-Z0-9/_.-]+", strings_content)
    if len(paths) > 10:
        vulnerabilities.append(f"Found {len(paths)} file paths (potential info disclosure)")

except Exception as e:
    vulnerabilities.append(f"String analysis failed: {e}")

# Save vulnerability assessment
with open("security_assessment.json", "w") as f:
    json.dump({
        "vulnerabilities": vulnerabilities,
        "risk_level": "HIGH" if len(vulnerabilities) > 3 else "MEDIUM" if vulnerabilities else "LOW",
        "total_issues": len(vulnerabilities)
    }, f, indent=2)

print(f"Security assessment: {len(vulnerabilities)} potential issues found")
EOF

log "Analysis complete! Check $OUTPUT_DIR for results."