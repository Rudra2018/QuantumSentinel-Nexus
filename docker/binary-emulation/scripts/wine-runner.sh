#!/bin/bash
# QuantumSentinel WINE Binary Runner
# Safe execution of Windows binaries with monitoring

set -euo pipefail

# Configuration
BINARY_PATH=""
EXECUTION_TIME=30
MONITOR_NETWORK=false
MONITOR_REGISTRY=false
OUTPUT_DIR="/analysis/results"
WINE_ARCH="win64"

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

QuantumSentinel WINE Binary Runner

OPTIONS:
    -t, --time SEC          Execution time in seconds (default: 30)
    -a, --arch ARCH         Wine architecture: win32, win64 (default: win64)
    -n, --network           Monitor network activity
    -r, --registry          Monitor registry changes
    -o, --output DIR        Output directory (default: /analysis/results)
    -h, --help             Show this help message

EXAMPLES:
    $0 /analysis/binaries/malware.exe
    $0 --time 60 --network --registry sample.exe
    $0 --arch win32 ./legacy_app.exe

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--time)
                EXECUTION_TIME="$2"
                shift 2
                ;;
            -a|--arch)
                WINE_ARCH="$2"
                shift 2
                ;;
            -n|--network)
                MONITOR_NETWORK=true
                shift
                ;;
            -r|--registry)
                MONITOR_REGISTRY=true
                shift
                ;;
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

setup_wine_env() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    EXECUTION_DIR="$OUTPUT_DIR/wine_${binary_name}_${timestamp}"
    mkdir -p "$EXECUTION_DIR"/{logs,traces,registry,network}

    print_info "Execution directory: $EXECUTION_DIR"

    # Set Wine environment
    export WINEARCH="$WINE_ARCH"
    export WINEPREFIX="$EXECUTION_DIR/wine_prefix"

    print_info "Initializing Wine prefix..."
    wineboot --init >/dev/null 2>&1

    # Configure Wine for headless operation
    winetricks -q settings win10 >/dev/null 2>&1
}

start_monitoring() {
    print_info "Starting monitoring services..."

    # Network monitoring
    if [[ "$MONITOR_NETWORK" == "true" ]]; then
        print_info "Starting network monitoring..."
        tcpdump -i any -w "$EXECUTION_DIR/traces/network.pcap" &
        TCPDUMP_PID=$!
        echo $TCPDUMP_PID > "$EXECUTION_DIR/logs/tcpdump.pid"
    fi

    # Process monitoring
    print_info "Starting process monitoring..."
    ps aux > "$EXECUTION_DIR/logs/processes_before.txt"
}

stop_monitoring() {
    print_info "Stopping monitoring services..."

    # Stop tcpdump
    if [[ -f "$EXECUTION_DIR/logs/tcpdump.pid" ]]; then
        local tcpdump_pid
        tcpdump_pid=$(cat "$EXECUTION_DIR/logs/tcpdump.pid")
        kill $tcpdump_pid 2>/dev/null || true
        rm -f "$EXECUTION_DIR/logs/tcpdump.pid"
    fi

    # Final process state
    ps aux > "$EXECUTION_DIR/logs/processes_after.txt"
}

backup_registry() {
    if [[ "$MONITOR_REGISTRY" == "true" ]]; then
        print_info "Backing up registry..."
        wine regedit /E "$EXECUTION_DIR/registry/registry_before.reg" 2>/dev/null || true
    fi
}

capture_registry_changes() {
    if [[ "$MONITOR_REGISTRY" == "true" ]]; then
        print_info "Capturing registry changes..."
        wine regedit /E "$EXECUTION_DIR/registry/registry_after.reg" 2>/dev/null || true

        # Compare registries if both exist
        if [[ -f "$EXECUTION_DIR/registry/registry_before.reg" && -f "$EXECUTION_DIR/registry/registry_after.reg" ]]; then
            diff "$EXECUTION_DIR/registry/registry_before.reg" "$EXECUTION_DIR/registry/registry_after.reg" > "$EXECUTION_DIR/registry/registry_changes.diff" 2>/dev/null || true
        fi
    fi
}

run_binary() {
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    print_info "Running Windows binary with WINE..."
    print_warning "Execution will run for $EXECUTION_TIME seconds"

    local execution_log="$EXECUTION_DIR/logs/execution.log"

    # Start monitoring
    start_monitoring
    backup_registry

    # Build Wine command
    local wine_cmd=("wine" "$BINARY_PATH")

    # Record execution details
    {
        echo "=== WINE Execution Started ==="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Wine Architecture: $WINE_ARCH"
        echo "Wine Prefix: $WINEPREFIX"
        echo "Start Time: $(date)"
        echo "==============================="
        echo
    } > "$execution_log"

    # Run with timeout and capture output
    if timeout "$EXECUTION_TIME" "${wine_cmd[@]}" >> "$execution_log" 2>&1; then
        print_success "Execution completed successfully"
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            print_warning "Execution terminated due to timeout"
        else
            print_warning "Execution terminated with exit code: $exit_code"
        fi
    fi

    # Stop monitoring and capture final state
    capture_registry_changes
    stop_monitoring

    {
        echo
        echo "==============================="
        echo "End Time: $(date)"
        echo "=== WINE Execution Finished ==="
    } >> "$execution_log"
}

analyze_execution() {
    print_info "Analyzing execution traces..."

    local analysis_file="$EXECUTION_DIR/logs/execution_analysis.txt"

    {
        echo "=== WINE Execution Analysis ==="
        echo "Analysis Date: $(date)"
        echo

        # Process analysis
        echo "=== Process Changes ==="
        if [[ -f "$EXECUTION_DIR/logs/processes_before.txt" && -f "$EXECUTION_DIR/logs/processes_after.txt" ]]; then
            diff "$EXECUTION_DIR/logs/processes_before.txt" "$EXECUTION_DIR/logs/processes_after.txt" | grep "^>" | head -10 || echo "No new processes detected"
        fi
        echo

        # Network analysis
        if [[ -f "$EXECUTION_DIR/traces/network.pcap" ]]; then
            echo "=== Network Activity ==="
            if command -v tcpdump >/dev/null 2>&1; then
                tcpdump -r "$EXECUTION_DIR/traces/network.pcap" -n 2>/dev/null | head -10 || echo "No network activity"
            fi
            echo
        fi

        # Registry changes
        if [[ -f "$EXECUTION_DIR/registry/registry_changes.diff" ]]; then
            echo "=== Registry Changes ==="
            head -20 "$EXECUTION_DIR/registry/registry_changes.diff" || echo "No registry changes"
            echo
        fi

        # Wine logs
        echo "=== Wine Debug Output ==="
        if [[ -f "$HOME/.wine/wine.log" ]]; then
            tail -20 "$HOME/.wine/wine.log" 2>/dev/null || echo "No Wine debug log"
        fi

    } > "$analysis_file"

    print_success "Execution analysis saved to: $analysis_file"
}

generate_wine_report() {
    print_info "Generating WINE execution report..."

    local report_file="$EXECUTION_DIR/wine_execution_report.txt"
    local binary_name
    binary_name=$(basename "$BINARY_PATH")

    {
        echo "==================================================="
        echo "QuantumSentinel WINE Execution Report"
        echo "==================================================="
        echo "Binary: $binary_name"
        echo "Path: $BINARY_PATH"
        echo "Wine Architecture: $WINE_ARCH"
        echo "Execution Time: ${EXECUTION_TIME}s"
        echo "Network Monitoring: $MONITOR_NETWORK"
        echo "Registry Monitoring: $MONITOR_REGISTRY"
        echo "Report Date: $(date)"
        echo

        if [[ -f "$EXECUTION_DIR/logs/execution_analysis.txt" ]]; then
            cat "$EXECUTION_DIR/logs/execution_analysis.txt"
        fi

        echo
        echo "=== Generated Files ==="
        find "$EXECUTION_DIR" -type f | sed "s|$EXECUTION_DIR/||" | sort

    } > "$report_file"

    print_success "WINE execution report generated: $report_file"
}

cleanup() {
    print_info "Cleaning up..."
    stop_monitoring

    # Clean up Wine processes
    wineserver -k 2>/dev/null || true

    print_success "Cleanup completed"
}

# Trap for cleanup on exit
trap cleanup EXIT

main() {
    print_info "QuantumSentinel WINE Binary Runner Starting..."

    parse_args "$@"
    setup_wine_env
    run_binary
    analyze_execution
    generate_wine_report

    print_success "WINE execution completed successfully!"
    print_info "Results available in: $EXECUTION_DIR"
}

main "$@"