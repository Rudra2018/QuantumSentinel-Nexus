#!/bin/bash
# QuantumSentinel Binary Emulation Script
# Safe binary execution with monitoring and analysis

set -euo pipefail

# Configuration
BINARY_PATH=""
EMULATION_TIME=30
MONITOR_NETWORK=false
MONITOR_FILES=false
ARCHITECTURE=""
OUTPUT_DIR="/analysis/results"
SANDBOX_MODE=true

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

QuantumSentinel Binary Emulation Script

OPTIONS:
    -t, --time SEC          Emulation time in seconds (default: 30)
    -a, --arch ARCH         Force architecture (auto-detect by default)
    -n, --network           Monitor network activity
    -f, --files             Monitor file system activity
    -o, --output DIR        Output directory (default: /analysis/results)
    --no-sandbox            Disable sandbox mode (DANGEROUS)
    -h, --help             Show this help message

SUPPORTED ARCHITECTURES:
    x86, x86-64, arm, arm64, mips, mips64, ppc, ppc64

EXAMPLES:
    $0 /analysis/binaries/sample.exe
    $0 --time 60 --network --files malware.bin
    $0 --arch arm ./arm_binary

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--time)
                EMULATION_TIME="$2"
                shift 2
                ;;
            -a|--arch)
                ARCHITECTURE="$2"
                shift 2
                ;;
            -n|--network)
                MONITOR_NETWORK=true
                shift
                ;;
            -f|--files)
                MONITOR_FILES=true
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --no-sandbox)
                SANDBOX_MODE=false
                shift
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

detect_architecture() {
    if [[ -n "$ARCHITECTURE" ]]; then
        print_info "Using specified architecture: $ARCHITECTURE"
        return
    fi

    local file_output
    file_output=$(file "$BINARY_PATH")

    if echo "$file_output" | grep -q "x86-64"; then
        ARCHITECTURE="x86-64"
    elif echo "$file_output" | grep -q "i386\|80386"; then
        ARCHITECTURE="x86"
    elif echo "$file_output" | grep -q "ARM aarch64"; then
        ARCHITECTURE="arm64"
    elif echo "$file_output" | grep -q "ARM"; then
        ARCHITECTURE="arm"
    elif echo "$file_output" | grep -q "MIPS64"; then
        ARCHITECTURE="mips64"
    elif echo "$file_output" | grep -q "MIPS"; then
        ARCHITECTURE="mips"
    elif echo "$file_output" | grep -q "PowerPC 64"; then
        ARCHITECTURE="ppc64"
    elif echo "$file_output" | grep -q "PowerPC"; then
        ARCHITECTURE="ppc"
    else
        print_warning "Could not detect architecture, defaulting to x86-64"
        ARCHITECTURE="x86-64"
    fi

    print_info "Detected architecture: $ARCHITECTURE"
}

setup_emulation_env() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    EMULATION_DIR="$OUTPUT_DIR/emulation_${binary_name}_${timestamp}"
    mkdir -p "$EMULATION_DIR"/{logs,traces,sandbox}

    print_info "Emulation directory: $EMULATION_DIR"

    # Set up sandbox if enabled
    if [[ "$SANDBOX_MODE" == "true" ]]; then
        setup_sandbox
    fi
}

setup_sandbox() {
    print_info "Setting up sandbox environment..."

    local sandbox_dir="$EMULATION_DIR/sandbox"

    # Create minimal filesystem structure
    mkdir -p "$sandbox_dir"/{bin,lib,tmp,proc,dev}

    # Copy essential libraries (if available)
    if [[ -d "/lib" ]]; then
        cp -r /lib/* "$sandbox_dir/lib/" 2>/dev/null || true
    fi

    # Create minimal /dev entries
    mknod "$sandbox_dir/dev/null" c 1 3 2>/dev/null || true
    mknod "$sandbox_dir/dev/zero" c 1 5 2>/dev/null || true

    print_success "Sandbox environment created"
}

get_qemu_binary() {
    case "$ARCHITECTURE" in
        "x86")
            echo "qemu-i386"
            ;;
        "x86-64")
            echo "qemu-x86_64"
            ;;
        "arm")
            echo "qemu-arm"
            ;;
        "arm64")
            echo "qemu-aarch64"
            ;;
        "mips")
            echo "qemu-mips"
            ;;
        "mips64")
            echo "qemu-mips64"
            ;;
        "ppc")
            echo "qemu-ppc"
            ;;
        "ppc64")
            echo "qemu-ppc64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCHITECTURE"
            exit 1
            ;;
    esac
}

start_monitoring() {
    print_info "Starting monitoring services..."

    # Network monitoring
    if [[ "$MONITOR_NETWORK" == "true" ]] && command -v tcpdump >/dev/null 2>&1; then
        print_info "Starting network monitoring..."
        tcpdump -i any -w "$EMULATION_DIR/traces/network.pcap" &
        TCPDUMP_PID=$!
        echo $TCPDUMP_PID > "$EMULATION_DIR/logs/tcpdump.pid"
    fi

    # File system monitoring
    if [[ "$MONITOR_FILES" == "true" ]] && command -v inotifywait >/dev/null 2>&1; then
        print_info "Starting file system monitoring..."
        inotifywait -m -r /tmp --format '%T %w %f %e' --timefmt '%Y-%m-%d %H:%M:%S' \
            > "$EMULATION_DIR/traces/filesystem.log" &
        INOTIFY_PID=$!
        echo $INOTIFY_PID > "$EMULATION_DIR/logs/inotify.pid"
    fi
}

stop_monitoring() {
    print_info "Stopping monitoring services..."

    # Stop tcpdump
    if [[ -f "$EMULATION_DIR/logs/tcpdump.pid" ]]; then
        local tcpdump_pid
        tcpdump_pid=$(cat "$EMULATION_DIR/logs/tcpdump.pid")
        kill $tcpdump_pid 2>/dev/null || true
        rm -f "$EMULATION_DIR/logs/tcpdump.pid"
    fi

    # Stop inotify
    if [[ -f "$EMULATION_DIR/logs/inotify.pid" ]]; then
        local inotify_pid
        inotify_pid=$(cat "$EMULATION_DIR/logs/inotify.pid")
        kill $inotify_pid 2>/dev/null || true
        rm -f "$EMULATION_DIR/logs/inotify.pid"
    fi
}

run_emulation() {
    local qemu_binary
    qemu_binary=$(get_qemu_binary)

    if ! command -v "$qemu_binary" >/dev/null 2>&1; then
        print_error "$qemu_binary not found. Please install QEMU with $ARCHITECTURE support."
        exit 1
    fi

    print_info "Starting emulation with $qemu_binary..."
    print_warning "Emulation will run for $EMULATION_TIME seconds"

    local emulation_log="$EMULATION_DIR/logs/emulation.log"
    local strace_log="$EMULATION_DIR/traces/strace.log"

    # Start monitoring
    start_monitoring

    # Build QEMU command
    local qemu_cmd=("$qemu_binary")

    # Add strace if available
    if command -v strace >/dev/null 2>&1; then
        qemu_cmd=("strace" "-f" "-o" "$strace_log" "$qemu_binary")
    fi

    # Add QEMU options
    qemu_cmd+=("-strace")

    # Add sandbox options if enabled
    if [[ "$SANDBOX_MODE" == "true" ]]; then
        qemu_cmd+=("-chroot" "$EMULATION_DIR/sandbox")
    fi

    # Add the binary
    qemu_cmd+=("$BINARY_PATH")

    # Run emulation with timeout
    {
        echo "=== Emulation Started ==="
        echo "Command: ${qemu_cmd[*]}"
        echo "Start Time: $(date)"
        echo "Architecture: $ARCHITECTURE"
        echo "Sandbox Mode: $SANDBOX_MODE"
        echo "=============================="
        echo
    } > "$emulation_log"

    if timeout "$EMULATION_TIME" "${qemu_cmd[@]}" >> "$emulation_log" 2>&1; then
        print_success "Emulation completed successfully"
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            print_warning "Emulation terminated due to timeout"
        else
            print_warning "Emulation terminated with exit code: $exit_code"
        fi
    fi

    # Stop monitoring
    stop_monitoring

    {
        echo
        echo "=============================="
        echo "End Time: $(date)"
        echo "=== Emulation Finished ==="
    } >> "$emulation_log"
}

analyze_traces() {
    print_info "Analyzing emulation traces..."

    local analysis_file="$EMULATION_DIR/logs/trace_analysis.txt"

    {
        echo "=== Emulation Trace Analysis ==="
        echo "Analysis Date: $(date)"
        echo

        # System call analysis
        if [[ -f "$EMULATION_DIR/traces/strace.log" ]]; then
            echo "=== System Call Summary ==="
            grep -o '^[^(]*' "$EMULATION_DIR/traces/strace.log" 2>/dev/null | \
                sort | uniq -c | sort -nr | head -20 || echo "No system calls found"
            echo

            echo "=== Suspicious System Calls ==="
            grep -E "(execve|clone|fork|socket|connect|open|write)" \
                "$EMULATION_DIR/traces/strace.log" 2>/dev/null | head -10 || echo "None found"
            echo
        fi

        # Network activity analysis
        if [[ -f "$EMULATION_DIR/traces/network.pcap" ]]; then
            echo "=== Network Activity ==="
            if command -v tcpdump >/dev/null 2>&1; then
                tcpdump -r "$EMULATION_DIR/traces/network.pcap" -n 2>/dev/null | head -10 || echo "No network activity"
            else
                echo "Network capture available but tcpdump not found for analysis"
            fi
            echo
        fi

        # File system activity
        if [[ -f "$EMULATION_DIR/traces/filesystem.log" ]]; then
            echo "=== File System Activity ==="
            head -20 "$EMULATION_DIR/traces/filesystem.log" 2>/dev/null || echo "No file system activity"
            echo
        fi

        echo "=== Files Created ==="
        find "$EMULATION_DIR" -type f -newer "$EMULATION_DIR" 2>/dev/null | head -10 || echo "None"

    } > "$analysis_file"

    print_success "Trace analysis saved to: $analysis_file"
}

generate_emulation_report() {
    print_info "Generating emulation report..."

    local report_file="$EMULATION_DIR/emulation_report.txt"
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    {
        echo "=================================================="
        echo "QuantumSentinel Binary Emulation Report"
        echo "=================================================="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Architecture: $ARCHITECTURE"
        echo "Emulation Time: ${EMULATION_TIME}s"
        echo "Sandbox Mode: $SANDBOX_MODE"
        echo "Network Monitoring: $MONITOR_NETWORK"
        echo "File Monitoring: $MONITOR_FILES"
        echo "Report Date: $(date)"
        echo

        if [[ -f "$EMULATION_DIR/logs/trace_analysis.txt" ]]; then
            cat "$EMULATION_DIR/logs/trace_analysis.txt"
        fi

        echo
        echo "=== Generated Files ==="
        find "$EMULATION_DIR" -type f | sed "s|$EMULATION_DIR/||" | sort

    } > "$report_file"

    print_success "Emulation report generated: $report_file"
}

cleanup() {
    print_info "Cleaning up..."
    stop_monitoring
    print_success "Cleanup completed"
}

# Trap for cleanup on exit
trap cleanup EXIT

main() {
    print_info "QuantumSentinel Binary Emulation Starting..."

    parse_args "$@"
    detect_architecture
    setup_emulation_env
    run_emulation
    analyze_traces
    generate_emulation_report

    print_success "Emulation completed successfully!"
    print_info "Results available in: $EMULATION_DIR"
}

main "$@"