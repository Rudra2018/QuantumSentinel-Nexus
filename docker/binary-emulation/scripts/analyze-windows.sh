#!/bin/bash
# QuantumSentinel Windows Binary Analysis Script
# PE analysis with WINE integration

set -euo pipefail

# Configuration
BINARY_PATH=""
OUTPUT_DIR="/analysis/results"
TIMEOUT=300
VERBOSE=false
ANALYSIS_TYPE="full"

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

QuantumSentinel Windows Binary Analysis Script

OPTIONS:
    -o, --output DIR        Output directory (default: /analysis/results)
    -t, --timeout SEC       Analysis timeout in seconds (default: 300)
    -v, --verbose           Enable verbose output
    --type TYPE             Analysis type: full, static, dynamic (default: full)
    -h, --help             Show this help message

EXAMPLES:
    $0 /analysis/binaries/malware.exe
    $0 --type static --output /tmp/results sample.exe
    $0 --verbose --timeout 600 ransomware.exe

EOF
}

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
            --type)
                ANALYSIS_TYPE="$2"
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

init_analysis() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    ANALYSIS_DIR="$OUTPUT_DIR/windows_${binary_name}_${timestamp}"
    mkdir -p "$ANALYSIS_DIR"/{static,dynamic,logs,reports}

    print_info "Initializing Windows binary analysis for: $binary_name"
    print_info "Analysis directory: $ANALYSIS_DIR"

    # Create analysis log
    LOGFILE="$ANALYSIS_DIR/logs/analysis.log"
    exec 1> >(tee -a "$LOGFILE")
    exec 2> >(tee -a "$LOGFILE" >&2)
}

analyze_pe_structure() {
    print_info "Analyzing PE structure..."

    local pe_file="$ANALYSIS_DIR/static/pe_analysis.txt"

    {
        echo "=== PE File Analysis ==="
        echo "File: $BINARY_PATH"
        echo "Analysis Date: $(date)"
        echo

        # Basic file information
        echo "=== Basic Information ==="
        echo "Size: $(stat -c%s "$BINARY_PATH") bytes"
        echo "Type: $(file "$BINARY_PATH")"
        echo "MD5: $(md5sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$BINARY_PATH" | cut -d' ' -f1)"
        echo

        # PE analysis with Python
        if command -v python3 >/dev/null 2>&1; then
            python3 << 'EOF'
import sys
import os
sys.path.append('/analysis')

try:
    import pefile
    import hashlib

    pe_path = os.environ.get('BINARY_PATH')

    print("=== PE Header Analysis ===")
    pe = pefile.PE(pe_path)

    print(f"Machine Type: {hex(pe.FILE_HEADER.Machine)}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
    print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
    print()

    print("=== Sections ===")
    for section in pe.sections:
        print(f"Name: {section.Name.decode().rstrip('\x00')}")
        print(f"  Virtual Address: {hex(section.VirtualAddress)}")
        print(f"  Virtual Size: {hex(section.Misc_VirtualSize)}")
        print(f"  Raw Size: {hex(section.SizeOfRawData)}")
        print(f"  Characteristics: {hex(section.Characteristics)}")
        print()

    print("=== Imports ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:10]:  # Limit to first 10
            print(f"DLL: {entry.dll.decode()}")
            for imp in entry.imports[:5]:  # Limit to first 5 per DLL
                print(f"  - {imp.name.decode() if imp.name else f'Ordinal {imp.ordinal}'}")
            print()

    print("=== Exports ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:10]:  # Limit to first 10
            print(f"  - {exp.name.decode() if exp.name else f'Ordinal {exp.ordinal}'}")

    pe.close()

except ImportError:
    print("pefile not available, skipping detailed PE analysis")
except Exception as e:
    print(f"Error analyzing PE: {e}")
EOF
        fi

        echo
        echo "=== Strings Analysis ==="
        strings "$BINARY_PATH" | head -50
        echo

        echo "=== Suspicious Strings ==="
        strings "$BINARY_PATH" | grep -iE "(password|admin|key|token|http|ftp|smtp|sql)" | head -20 || echo "None found"

    } > "$pe_file"

    print_success "PE analysis saved to: $pe_file"
}

analyze_static_windows() {
    print_info "Performing static Windows analysis..."

    local static_dir="$ANALYSIS_DIR/static"

    # Resource analysis
    if command -v python3 >/dev/null 2>&1; then
        print_info "Analyzing PE resources..."

        python3 << 'EOF' > "$static_dir/resources.txt"
import sys
import os
sys.path.append('/analysis')

try:
    import pefile

    pe_path = os.environ.get('BINARY_PATH')
    pe = pefile.PE(pe_path)

    print("=== PE Resources ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                print(f"Resource Type: {resource_type.name}")
            else:
                print(f"Resource Type ID: {resource_type.struct.Id}")

            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            print(f"  Size: {len(data)} bytes")
                            if len(data) > 100:
                                print(f"  Preview: {data[:100]}")
                            print()

    pe.close()

except ImportError:
    print("pefile not available")
except Exception as e:
    print(f"Error: {e}")
EOF
    fi

    # Entropy analysis
    print_info "Calculating entropy..."
    python3 << 'EOF' > "$static_dir/entropy.txt"
import os
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0

    counter = Counter(data)
    length = len(data)
    entropy = 0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

pe_path = os.environ.get('BINARY_PATH')
with open(pe_path, 'rb') as f:
    data = f.read()

chunk_size = 1024
print("=== Entropy Analysis ===")
print(f"Overall entropy: {calculate_entropy(data):.2f}")
print("\nSection entropy (1KB chunks):")

for i in range(0, min(len(data), 10240), chunk_size):  # First 10KB
    chunk = data[i:i+chunk_size]
    entropy = calculate_entropy(chunk)
    print(f"Offset {i:04x}: {entropy:.2f}")
    if entropy > 7.5:
        print("  ^ High entropy detected (possible packing/encryption)")
EOF

    print_success "Static Windows analysis completed"
}

analyze_dynamic_windows() {
    if [[ "$ANALYSIS_TYPE" == "static" ]]; then
        print_info "Skipping dynamic analysis (static mode)"
        return
    fi

    print_info "Performing dynamic Windows analysis..."

    local dynamic_dir="$ANALYSIS_DIR/dynamic"

    # Check if WINE is available
    if ! command -v wine >/dev/null 2>&1; then
        print_warning "WINE not available, skipping dynamic analysis"
        return
    fi

    # Set up Wine environment
    export WINEARCH=win64
    export WINEPREFIX="$dynamic_dir/wine_prefix"

    print_info "Initializing Wine prefix..."
    wineboot --init >/dev/null 2>&1

    # Run with monitoring using wine-runner.sh
    if [[ -f "/usr/local/bin/wine-runner.sh" ]]; then
        print_info "Running dynamic analysis with WINE..."
        /usr/local/bin/wine-runner.sh --time 60 --network --registry --output "$dynamic_dir" "$BINARY_PATH"
    else
        print_warning "wine-runner.sh not found, running basic Wine execution"
        timeout 60 wine "$BINARY_PATH" > "$dynamic_dir/wine_output.txt" 2>&1 || true
    fi

    print_success "Dynamic Windows analysis completed"
}

generate_windows_report() {
    print_info "Generating Windows analysis report..."

    local report_file="$ANALYSIS_DIR/reports/windows_analysis_report.txt"
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    {
        echo "==================================================="
        echo "QuantumSentinel Windows Binary Analysis Report"
        echo "==================================================="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Analysis Type: $ANALYSIS_TYPE"
        echo "Analysis Date: $(date)"
        echo "Analysis Directory: $ANALYSIS_DIR"
        echo

        echo "=== Analysis Summary ==="
        echo "Timeout: ${TIMEOUT}s"
        echo "Verbose: $VERBOSE"
        echo

        if [[ -f "$ANALYSIS_DIR/static/pe_analysis.txt" ]]; then
            echo "=== PE Analysis Results ==="
            head -30 "$ANALYSIS_DIR/static/pe_analysis.txt"
            echo
        fi

        if [[ -f "$ANALYSIS_DIR/static/entropy.txt" ]]; then
            echo "=== Entropy Analysis ==="
            cat "$ANALYSIS_DIR/static/entropy.txt"
            echo
        fi

        if [[ -d "$ANALYSIS_DIR/dynamic" ]]; then
            echo "=== Dynamic Analysis ==="
            echo "Dynamic analysis performed with WINE"
            if [[ -f "$ANALYSIS_DIR/dynamic/wine_execution_report.txt" ]]; then
                echo "Wine execution report available"
            fi
            echo
        fi

        echo "=== Files Generated ==="
        find "$ANALYSIS_DIR" -type f | sed "s|$ANALYSIS_DIR/||" | sort

    } > "$report_file"

    print_success "Windows analysis report generated: $report_file"
}

main() {
    print_info "QuantumSentinel Windows Binary Analysis Starting..."

    parse_args "$@"
    init_analysis

    # Run analysis based on type
    analyze_pe_structure

    case "$ANALYSIS_TYPE" in
        "static")
            analyze_static_windows
            ;;
        "dynamic")
            analyze_static_windows
            analyze_dynamic_windows
            ;;
        "full"|*)
            analyze_static_windows
            analyze_dynamic_windows
            ;;
    esac

    generate_windows_report

    print_success "Windows binary analysis completed successfully!"
    print_info "Results available in: $ANALYSIS_DIR"
}

main "$@"