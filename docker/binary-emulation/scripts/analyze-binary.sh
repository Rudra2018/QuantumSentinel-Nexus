#!/bin/bash
# QuantumSentinel Binary Analysis Script for Docker Environment
# Comprehensive binary security analysis with multiple tools

set -euo pipefail

# Configuration
BINARY_PATH=""
OUTPUT_DIR="/analysis/results"
TIMEOUT=300  # 5 minutes
VERBOSE=false
TOOLS="all"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] BINARY_PATH

QuantumSentinel Binary Analysis Script

OPTIONS:
    -o, --output DIR      Output directory (default: /analysis/results)
    -t, --timeout SEC     Analysis timeout in seconds (default: 300)
    -v, --verbose         Enable verbose output
    --tools TOOLS         Tools to use: all, static, dynamic, ml (default: all)
    -h, --help           Show this help message

EXAMPLES:
    $0 /analysis/binaries/sample.exe
    $0 --tools static --output /tmp/results /bin/ls
    $0 --verbose --timeout 600 malware.bin

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --tools)
                TOOLS="$2"
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

# Initialize analysis environment
init_analysis() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    ANALYSIS_DIR="$OUTPUT_DIR/${binary_name}_${timestamp}"
    mkdir -p "$ANALYSIS_DIR"/{static,dynamic,logs,reports}

    print_info "Initializing analysis for: $binary_name"
    print_info "Analysis directory: $ANALYSIS_DIR"

    # Create analysis log
    LOGFILE="$ANALYSIS_DIR/logs/analysis.log"
    exec 1> >(tee -a "$LOGFILE")
    exec 2> >(tee -a "$LOGFILE" >&2)
}

# Basic file information
analyze_file_info() {
    print_info "Extracting basic file information..."

    local info_file="$ANALYSIS_DIR/static/file_info.txt"

    {
        echo "=== File Information ==="
        echo "File: $BINARY_PATH"
        echo "Size: $(stat -c%s "$BINARY_PATH") bytes"
        echo "Type: $(file "$BINARY_PATH")"
        echo "MD5: $(md5sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo "SHA1: $(sha1sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo

        if command -v checksec >/dev/null 2>&1; then
            echo "=== Security Features ==="
            checksec --file="$BINARY_PATH" 2>/dev/null || echo "Checksec analysis failed"
            echo
        fi

        echo "=== Strings (first 50) ==="
        strings "$BINARY_PATH" | head -50
        echo

        echo "=== File Headers ==="
        hexdump -C "$BINARY_PATH" | head -20

    } > "$info_file"

    print_success "File information saved to: $info_file"
}

# Static analysis
analyze_static() {
    print_info "Performing static analysis..."

    local static_dir="$ANALYSIS_DIR/static"

    # Disassembly
    if command -v objdump >/dev/null 2>&1; then
        print_info "Running objdump disassembly..."
        objdump -d "$BINARY_PATH" > "$static_dir/disassembly.txt" 2>/dev/null || true
    fi

    # Readelf for ELF files
    if file "$BINARY_PATH" | grep -q "ELF"; then
        print_info "Running ELF analysis..."
        {
            echo "=== ELF Header ==="
            readelf -h "$BINARY_PATH" 2>/dev/null
            echo
            echo "=== Section Headers ==="
            readelf -S "$BINARY_PATH" 2>/dev/null
            echo
            echo "=== Program Headers ==="
            readelf -l "$BINARY_PATH" 2>/dev/null
            echo
            echo "=== Dynamic Section ==="
            readelf -d "$BINARY_PATH" 2>/dev/null
            echo
            echo "=== Symbols ==="
            readelf -s "$BINARY_PATH" 2>/dev/null
        } > "$static_dir/elf_analysis.txt"
    fi

    # Radare2 analysis
    if command -v r2 >/dev/null 2>&1; then
        print_info "Running Radare2 analysis..."
        timeout $TIMEOUT r2 -A -c "iI; fs symbols; f" "$BINARY_PATH" > "$static_dir/r2_analysis.txt" 2>/dev/null || true
    fi

    print_success "Static analysis completed"
}

# Dynamic analysis
analyze_dynamic() {
    print_info "Performing dynamic analysis..."

    local dynamic_dir="$ANALYSIS_DIR/dynamic"

    # Check if binary is executable
    if [[ ! -x "$BINARY_PATH" ]]; then
        print_warning "Binary is not executable, skipping dynamic analysis"
        return
    fi

    # Strace analysis
    if command -v strace >/dev/null 2>&1; then
        print_info "Running strace analysis..."
        timeout $TIMEOUT strace -f -o "$dynamic_dir/strace.txt" "$BINARY_PATH" 2>/dev/null || true
    fi

    # Ltrace analysis
    if command -v ltrace >/dev/null 2>&1; then
        print_info "Running ltrace analysis..."
        timeout $TIMEOUT ltrace -f -o "$dynamic_dir/ltrace.txt" "$BINARY_PATH" 2>/dev/null || true
    fi

    # QEMU emulation if cross-architecture
    local arch
    arch=$(file "$BINARY_PATH" | grep -o -E "(x86-64|i386|ARM|MIPS)")
    if [[ -n "$arch" && "$arch" != "x86-64" ]]; then
        print_info "Running QEMU emulation for $arch..."
        case "$arch" in
            "i386")
                timeout $TIMEOUT qemu-i386 -strace "$BINARY_PATH" > "$dynamic_dir/qemu_i386.txt" 2>&1 || true
                ;;
            "ARM")
                timeout $TIMEOUT qemu-arm -strace "$BINARY_PATH" > "$dynamic_dir/qemu_arm.txt" 2>&1 || true
                ;;
            "MIPS")
                timeout $TIMEOUT qemu-mips -strace "$BINARY_PATH" > "$dynamic_dir/qemu_mips.txt" 2>&1 || true
                ;;
        esac
    fi

    print_success "Dynamic analysis completed"
}

# ML/AI Analysis
analyze_ml() {
    print_info "Performing ML/AI analysis..."

    local ml_dir="$ANALYSIS_DIR/reports"

    # Run Python-based ML analysis if available
    if command -v python3 >/dev/null 2>&1 && python3 -c "import capstone, lief" 2>/dev/null; then
        print_info "Running Python ML analysis..."

        # Create simple ML analysis script
        cat > "/tmp/ml_analysis.py" << 'EOF'
#!/usr/bin/env python3
import sys
import json
import hashlib
from pathlib import Path

def analyze_binary(binary_path):
    results = {
        'file_path': binary_path,
        'analysis_type': 'ml_basic',
        'findings': [],
        'metadata': {}
    }

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Basic analysis
        results['metadata'] = {
            'size': len(data),
            'entropy': calculate_entropy(data[:1024]),  # First 1KB
            'md5': hashlib.md5(data).hexdigest(),
            'suspicious_strings': find_suspicious_strings(data)
        }

        # Simple heuristics
        if results['metadata']['entropy'] > 7.5:
            results['findings'].append({
                'type': 'high_entropy',
                'severity': 'medium',
                'description': 'High entropy detected - possible packing/encryption'
            })

        if len(results['metadata']['suspicious_strings']) > 0:
            results['findings'].append({
                'type': 'suspicious_strings',
                'severity': 'low',
                'description': f"Found {len(results['metadata']['suspicious_strings'])} suspicious strings"
            })

    except Exception as e:
        results['error'] = str(e)

    return results

def calculate_entropy(data):
    if not data:
        return 0

    # Calculate byte frequency
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    # Calculate entropy
    import math
    entropy = 0
    data_len = len(data)
    for count in frequency.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def find_suspicious_strings(data):
    import re
    suspicious = []

    # Convert to string for pattern matching
    try:
        text = data.decode('utf-8', errors='ignore')
    except:
        text = str(data)

    patterns = [
        r'password[=:]',
        r'admin[=:]',
        r'http://[^\s]+',
        r'system\(',
        r'exec\(',
        r'cmd\.exe'
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        suspicious.extend(matches)

    return list(set(suspicious))[:10]  # Limit to 10 unique matches

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 ml_analysis.py <binary_path> <output_file>")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_file = sys.argv[2]

    results = analyze_binary(binary_path)

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"ML analysis completed. Results saved to: {output_file}")
EOF

        python3 /tmp/ml_analysis.py "$BINARY_PATH" "$ml_dir/ml_analysis.json"
        rm -f /tmp/ml_analysis.py
    fi

    print_success "ML analysis completed"
}

# Generate final report
generate_report() {
    print_info "Generating analysis report..."

    local report_file="$ANALYSIS_DIR/reports/analysis_report.txt"
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    {
        echo "=================================================="
        echo "QuantumSentinel Binary Analysis Report"
        echo "=================================================="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Analysis Date: $(date)"
        echo "Analysis Directory: $ANALYSIS_DIR"
        echo

        echo "=== Analysis Summary ==="
        echo "Tools Used: $TOOLS"
        echo "Timeout: ${TIMEOUT}s"
        echo

        if [[ -f "$ANALYSIS_DIR/static/file_info.txt" ]]; then
            echo "=== File Information ==="
            head -20 "$ANALYSIS_DIR/static/file_info.txt"
            echo
        fi

        if [[ -f "$ANALYSIS_DIR/reports/ml_analysis.json" ]]; then
            echo "=== ML Analysis Results ==="
            python3 -c "
import json
try:
    with open('$ANALYSIS_DIR/reports/ml_analysis.json') as f:
        data = json.load(f)
    print(f'Findings: {len(data.get(\"findings\", []))}')
    for finding in data.get('findings', [])[:5]:
        print(f'- {finding.get(\"type\", \"unknown\")}: {finding.get(\"description\", \"\")}')
except:
    print('Error reading ML analysis results')
            "
            echo
        fi

        echo "=== Files Generated ==="
        find "$ANALYSIS_DIR" -type f -name "*.txt" -o -name "*.json" | sed "s|$ANALYSIS_DIR/||" | sort

    } > "$report_file"

    print_success "Analysis report generated: $report_file"
}

# Main execution
main() {
    print_info "QuantumSentinel Binary Analysis Starting..."

    parse_args "$@"
    init_analysis

    # Run analysis based on tools selection
    case "$TOOLS" in
        "static")
            analyze_file_info
            analyze_static
            ;;
        "dynamic")
            analyze_file_info
            analyze_dynamic
            ;;
        "ml")
            analyze_file_info
            analyze_ml
            ;;
        "all"|*)
            analyze_file_info
            analyze_static
            analyze_dynamic
            analyze_ml
            ;;
    esac

    generate_report

    print_success "Analysis completed successfully!"
    print_info "Results available in: $ANALYSIS_DIR"
}

# Run main function with all arguments
main "$@"