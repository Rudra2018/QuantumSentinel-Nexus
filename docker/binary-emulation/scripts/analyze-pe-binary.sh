#!/bin/bash
# QuantumSentinel PE Binary Analysis Script
# Comprehensive analysis of Windows PE binaries

set -euo pipefail

PE_PATH="$1"
OUTPUT_DIR="/analysis/results/$(basename "$PE_PATH")_pe_analysis_$(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

if [ ! -f "$PE_PATH" ]; then
    error "PE file not found: $PE_PATH"
fi

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

log "Starting PE binary analysis for: $(basename "$PE_PATH")"

# Basic file information
log "=== Basic File Information ==="
file "$PE_PATH" > file_info.txt
ls -la "$PE_PATH" > file_stats.txt

# PE analysis with pefile
log "=== PE Structure Analysis ==="
python3 << EOF
import pefile
import json
import hashlib

try:
    pe = pefile.PE("$PE_PATH")

    # Calculate hashes
    with open("$PE_PATH", "rb") as f:
        data = f.read()

    pe_info = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": hex(pe.FILE_HEADER.Machine),
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": [],
        "imports": [],
        "exports": [],
        "version_info": {}
    }

    # Section information
    for section in pe.sections:
        pe_info["sections"].append({
            "name": section.Name.decode().rstrip('\x00'),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "characteristics": hex(section.Characteristics)
        })

    # Import table
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            functions = [imp.name.decode() if imp.name else f"Ordinal_{imp.ordinal}"
                        for imp in entry.imports]
            pe_info["imports"].append({
                "dll": dll_name,
                "functions": functions[:20]  # Limit to first 20
            })

    # Export table
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            pe_info["exports"].append({
                "name": exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}",
                "address": hex(exp.address)
            })

    # Version information
    if hasattr(pe, 'VS_VERSIONINFO'):
        for file_info in pe.FileInfo:
            for entry in file_info:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for key, value in st_entry.entries.items():
                            pe_info["version_info"][key.decode()] = value.decode()

    with open("pe_analysis.json", "w") as f:
        json.dump(pe_info, f, indent=2)

    print(f"✅ PE analysis completed")
    print(f"   Sections: {len(pe_info['sections'])}")
    print(f"   Imports: {len(pe_info['imports'])}")
    print(f"   Exports: {len(pe_info['exports'])}")

except Exception as e:
    print(f"❌ PE analysis failed: {e}")
EOF

# Security analysis
log "=== Security Analysis ==="
if command -v checksec >/dev/null 2>&1; then
    checksec --file="$PE_PATH" > security_features.txt 2>/dev/null || warn "checksec failed"
fi

# String extraction
log "=== String Analysis ==="
strings "$PE_PATH" | head -500 > strings.txt

# Radare2 analysis
log "=== Radare2 Analysis ==="
r2 -q -A -c "iI; iS; il; iz" "$PE_PATH" > radare2_analysis.txt 2>/dev/null || warn "Radare2 analysis failed"

# Generate summary
log "=== Generating Summary ==="
cat > analysis_summary.txt << EOL
QuantumSentinel PE Binary Analysis Report
=======================================
Binary: $(basename "$PE_PATH")
Analysis Date: $(date)
Output Directory: $OUTPUT_DIR

Files Generated:
- file_info.txt: Basic file information
- pe_analysis.json: PE structure analysis
- security_features.txt: Security features
- strings.txt: Extracted strings
- radare2_analysis.txt: Radare2 analysis

Analysis completed successfully!
EOL

log "PE analysis complete! Results in: $OUTPUT_DIR"