#!/bin/bash
# QuantumSentinel Minimal Binary Analysis Script
# Lightweight analysis for Alpine environment

set -euo pipefail

# Configuration
BINARY_PATH=""
OUTPUT_DIR="/analysis/results"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Usage: $0 [OPTIONS] BINARY_PATH

QuantumSentinel Minimal Binary Analysis Script

OPTIONS:
    -o, --output DIR      Output directory (default: /analysis/results)
    -h, --help           Show this help message

EXAMPLES:
    $0 /analysis/binaries/sample.bin
    $0 --output /tmp/results ./binary

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                BINARY_PATH="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$BINARY_PATH" ]]; then
        print_error "Binary path is required"
        usage
        exit 1
    fi

    if [[ ! -f "$BINARY_PATH" ]]; then
        print_error "Binary file not found: $BINARY_PATH"
        exit 1
    fi
}

init_minimal_analysis() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    ANALYSIS_DIR="$OUTPUT_DIR/minimal_${binary_name}_${timestamp}"
    mkdir -p "$ANALYSIS_DIR"

    print_info "Minimal analysis for: $binary_name"
    print_info "Analysis directory: $ANALYSIS_DIR"
}

analyze_basic_info() {
    print_info "Extracting basic information..."

    local info_file="$ANALYSIS_DIR/basic_info.txt"

    {
        echo "=== Minimal Binary Analysis ==="
        echo "File: $BINARY_PATH"
        echo "Analysis Date: $(date)"
        echo

        echo "=== File Information ==="
        echo "Size: $(stat -c%s "$BINARY_PATH") bytes"
        echo "Type: $(file "$BINARY_PATH")"
        echo "MD5: $(md5sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo

        echo "=== File Headers ==="
        hexdump -C "$BINARY_PATH" | head -10
        echo

        echo "=== Strings (first 30) ==="
        strings "$BINARY_PATH" | head -30
        echo

        echo "=== Suspicious Patterns ==="
        strings "$BINARY_PATH" | grep -iE "(http|ftp|password|admin|exec|shell|cmd)" | head -10 || echo "None found"

    } > "$info_file"

    print_success "Basic information saved to: $info_file"
}

analyze_elf_minimal() {
    if file "$BINARY_PATH" | grep -q "ELF"; then
        print_info "Performing minimal ELF analysis..."

        local elf_file="$ANALYSIS_DIR/elf_info.txt"

        {
            echo "=== ELF Information ==="
            readelf -h "$BINARY_PATH" 2>/dev/null || echo "Failed to read ELF header"
            echo

            echo "=== Program Headers ==="
            readelf -l "$BINARY_PATH" 2>/dev/null || echo "Failed to read program headers"
            echo

            echo "=== Dynamic Section ==="
            readelf -d "$BINARY_PATH" 2>/dev/null || echo "No dynamic section"

        } > "$elf_file"

        print_success "ELF analysis saved to: $elf_file"
    fi
}

quick_security_check() {
    print_info "Performing quick security check..."

    local security_file="$ANALYSIS_DIR/security_check.txt"

    {
        echo "=== Security Features Check ==="

        # Check for common security features
        if command -v readelf >/dev/null 2>&1 && file "$BINARY_PATH" | grep -q "ELF"; then
            echo "NX Bit (GNU_STACK):"
            readelf -l "$BINARY_PATH" | grep "GNU_STACK" | grep -q "RWE" && echo "  DISABLED (RWE)" || echo "  ENABLED"

            echo "PIE (Position Independent):"
            readelf -h "$BINARY_PATH" | grep -q "DYN" && echo "  ENABLED" || echo "  DISABLED"

            echo "RELRO:"
            readelf -d "$BINARY_PATH" | grep -q "BIND_NOW" && echo "  Full RELRO" || echo "  Partial/No RELRO"

            echo "Stack Canary Check:"
            readelf -s "$BINARY_PATH" | grep -q "__stack_chk" && echo "  ENABLED" || echo "  DISABLED"
        else
            echo "Not an ELF file or readelf not available"
        fi

        echo
        echo "=== Entropy Analysis ==="
        # Simple entropy calculation
        python3 << 'EOF'
import os
import math
from collections import Counter

def simple_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

binary_path = os.environ.get('BINARY_PATH')
with open(binary_path, 'rb') as f:
    data = f.read(1024)  # First 1KB only

entropy = simple_entropy(data)
print(f"First 1KB entropy: {entropy:.2f}")
if entropy > 7.5:
    print("HIGH ENTROPY - Possible packing/encryption")
elif entropy < 4.0:
    print("LOW ENTROPY - Likely uncompressed/plain text")
else:
    print("NORMAL ENTROPY")
EOF

    } > "$security_file"

    print_success "Security check saved to: $security_file"
}

generate_minimal_report() {
    print_info "Generating minimal report..."

    local report_file="$ANALYSIS_DIR/minimal_report.txt"
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    {
        echo "=============================================="
        echo "QuantumSentinel Minimal Binary Analysis Report"
        echo "=============================================="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Analysis Date: $(date)"
        echo

        if [[ -f "$ANALYSIS_DIR/basic_info.txt" ]]; then
            cat "$ANALYSIS_DIR/basic_info.txt"
            echo
        fi

        if [[ -f "$ANALYSIS_DIR/security_check.txt" ]]; then
            cat "$ANALYSIS_DIR/security_check.txt"
            echo
        fi

        echo "=== Analysis Files ==="
        ls -la "$ANALYSIS_DIR"

    } > "$report_file"

    print_success "Minimal report generated: $report_file"
}

main() {
    print_info "QuantumSentinel Minimal Binary Analysis Starting..."

    parse_args "$@"
    init_minimal_analysis
    analyze_basic_info
    analyze_elf_minimal
    quick_security_check
    generate_minimal_report

    print_success "Minimal analysis completed successfully!"
    print_info "Results available in: $ANALYSIS_DIR"
}

main "$@"